package com.kunal.attackpathvisualizer.integration;

import io.fabric8.kubernetes.api.model.ConfigMap;
import io.fabric8.kubernetes.api.model.ConfigMapBuilder;
import io.fabric8.kubernetes.api.model.HasMetadata;
import io.fabric8.kubernetes.api.model.IntOrString;
import io.fabric8.kubernetes.api.model.NamedContext;
import io.fabric8.kubernetes.api.model.Namespace;
import io.fabric8.kubernetes.api.model.NamespaceBuilder;
import io.fabric8.kubernetes.api.model.Pod;
import io.fabric8.kubernetes.api.model.PodBuilder;
import io.fabric8.kubernetes.api.model.Secret;
import io.fabric8.kubernetes.api.model.SecretBuilder;
import io.fabric8.kubernetes.api.model.Service;
import io.fabric8.kubernetes.api.model.ServiceAccount;
import io.fabric8.kubernetes.api.model.ServiceAccountBuilder;
import io.fabric8.kubernetes.api.model.ServiceBuilder;
import io.fabric8.kubernetes.api.model.rbac.ClusterRole;
import io.fabric8.kubernetes.api.model.rbac.ClusterRoleBinding;
import io.fabric8.kubernetes.api.model.rbac.ClusterRoleBindingBuilder;
import io.fabric8.kubernetes.api.model.rbac.ClusterRoleBuilder;
import io.fabric8.kubernetes.api.model.rbac.Role;
import io.fabric8.kubernetes.api.model.rbac.RoleBinding;
import io.fabric8.kubernetes.api.model.rbac.RoleBindingBuilder;
import io.fabric8.kubernetes.api.model.rbac.RoleBuilder;
import io.fabric8.kubernetes.client.Config;
import io.fabric8.kubernetes.client.ConfigBuilder;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientBuilder;
import io.fabric8.kubernetes.client.KubernetesClientException;

/**
 * Creates and removes the controlled resources used by the live integration tests.
 *
 * Safety rules:
 *  - Refuses to run unless the current kube context contains "minikube"
 *    (override with -Dattackpath.it.allowAnyCluster=true).
 *  - Every object it creates carries the label attackpath-it=true.
 *  - It only ever deletes its own two namespaces and its own cluster-scoped
 *    objects, and only if they carry that label.
 */
final class LiveClusterFixture implements AutoCloseable {

    static final String MANAGED_LABEL = "attackpath-it";
    static final String MANAGED_VALUE = "true";
    static final String ANNOTATION_KEY = "example.com/note";
    static final String ANNOTATION_VALUE = "known-annotation";

    static final String POD = "backend-pod";
    static final String SERVICE = "backend-service";
    static final String SA = "app-sa";
    static final String ROLE = "secret-reader";
    static final String ROLE_BINDING = "backend-secret-reader";
    static final String SECRET = "app-credentials";
    static final String CONFIG_MAP = "app-config";
    static final String DUMMY_SECRET_VALUE = "dummy-secret-value-do-not-use";
    static final String SA_TOKEN_TYPE = "kubernetes.io/service-account-token";

    final KubernetesClient client;
    final String ns;
    final String emptyNs;

    final String clusterRoleName;
    final String clusterRoleBindingName;
    private final String nsListerRoleName;
    private final String nsListerBindingName;

    Namespace namespaceObj;
    Namespace emptyNamespaceObj;
    ServiceAccount serviceAccountObj;
    Pod podObj;
    Service serviceObj;
    Role roleObj;
    ClusterRole clusterRoleObj;
    RoleBinding roleBindingObj;
    ClusterRoleBinding clusterRoleBindingObj;
    Secret secretObj;
    ConfigMap configMapObj;

    LiveClusterFixture(String ns) {
        this.ns = ns;
        this.emptyNs = ns + "-empty";
        this.clusterRoleName = ns + "-reader";
        this.clusterRoleBindingName = ns + "-reader-binding";
        this.nsListerRoleName = ns + "-ns-lister";
        this.nsListerBindingName = ns + "-ns-lister-binding";
        this.client = new KubernetesClientBuilder().build();
    }

    // ------------------------------------------------------------------
    // identities used by the error-handling tests
    // ------------------------------------------------------------------

    String deniedUser() {
        return "system:serviceaccount:" + ns + ":attackpath-denied";
    }

    String nsListerUser() {
        return "system:serviceaccount:" + ns + ":attackpath-nslister";
    }

    // ------------------------------------------------------------------
    // node id helpers (match GraphBuilder)
    // ------------------------------------------------------------------

    String id(String type, String name) {
        return type + ":" + ns + ":" + name;
    }

    static String clusterId(String type, String name) {
        return type + ":" + name;
    }

    // ------------------------------------------------------------------
    // lifecycle
    // ------------------------------------------------------------------

    void setUp() {
        assertSafeCluster();
        refuseIfUnmanaged(ns);
        refuseIfUnmanaged(emptyNs);
        cleanup(); // leftovers from an interrupted earlier run (managed objects only)
        try {
            create();
        } catch (RuntimeException e) {
            try {
                cleanup();
            } catch (RuntimeException suppressed) {
                e.addSuppressed(suppressed);
            }
            throw e;
        }
    }

    @Override
    public void close() {
        try {
            cleanup();
        } finally {
            client.close();
        }
    }

    private void assertSafeCluster() {
        if (Boolean.getBoolean("attackpath.it.allowAnyCluster")) {
            return;
        }
        NamedContext ctx = client.getConfiguration().getCurrentContext();
        String name = ctx == null ? "" : String.valueOf(ctx.getName());
        if (!name.toLowerCase().contains("minikube")) {
            throw new IllegalStateException(
                    "Refusing to run live tests: current kube context is '" + name
                            + "', not a minikube context. Run 'kubectl config use-context minikube' "
                            + "or pass -Dattackpath.it.allowAnyCluster=true.");
        }
    }

    private void refuseIfUnmanaged(String namespace) {
        Namespace existing = client.namespaces().withName(namespace).get();
        if (existing != null && !isManaged(existing)) {
            throw new IllegalStateException(
                    "Namespace '" + namespace + "' already exists and was not created by these tests "
                            + "(missing label " + MANAGED_LABEL + "=" + MANAGED_VALUE + "). Refusing to touch it.");
        }
    }

    private static boolean isManaged(HasMetadata r) {
        return r.getMetadata() != null
                && r.getMetadata().getLabels() != null
                && MANAGED_VALUE.equals(r.getMetadata().getLabels().get(MANAGED_LABEL));
    }

    // ------------------------------------------------------------------
    // creation
    // ------------------------------------------------------------------

    private void create() {
        namespaceObj = client.resource(namespace(ns)).create();
        emptyNamespaceObj = client.resource(namespace(emptyNs)).create();

        // ServiceAccount must exist before the Pod that uses it.
        serviceAccountObj = client.resource(new ServiceAccountBuilder()
                .withNewMetadata().withName(SA).withNamespace(ns)
                .addToLabels(MANAGED_LABEL, MANAGED_VALUE)
                .addToAnnotations(ANNOTATION_KEY, ANNOTATION_VALUE)
                .endMetadata()
                .build()).create();

        podObj = client.resource(new PodBuilder()
                .withNewMetadata().withName(POD).withNamespace(ns)
                .addToLabels("app", "backend")
                .addToLabels(MANAGED_LABEL, MANAGED_VALUE)
                .addToAnnotations(ANNOTATION_KEY, ANNOTATION_VALUE)
                .endMetadata()
                .withNewSpec()
                .withServiceAccountName(SA)
                .withTerminationGracePeriodSeconds(0L)
                .addNewContainer().withName("pause").withImage("registry.k8s.io/pause:3.9").endContainer()
                .endSpec()
                .build()).create();

        serviceObj = client.resource(new ServiceBuilder()
                .withNewMetadata().withName(SERVICE).withNamespace(ns)
                .addToLabels(MANAGED_LABEL, MANAGED_VALUE)
                .endMetadata()
                .withNewSpec()
                .addToSelector("app", "backend")
                .addNewPort().withName("http").withPort(80).withTargetPort(new IntOrString(8080)).endPort()
                .endSpec()
                .build()).create();

        roleObj = client.resource(new RoleBuilder()
                .withNewMetadata().withName(ROLE).withNamespace(ns)
                .addToLabels(MANAGED_LABEL, MANAGED_VALUE)
                .endMetadata()
                .addNewRule().withApiGroups("").withResources("secrets").withVerbs("get", "list").endRule()
                .build()).create();

        // Grants no Secret access: only get/list on namespaces.
        clusterRoleObj = client.resource(new ClusterRoleBuilder()
                .withNewMetadata().withName(clusterRoleName)
                .addToLabels(MANAGED_LABEL, MANAGED_VALUE)
                .endMetadata()
                .addNewRule().withApiGroups("").withResources("namespaces").withVerbs("get", "list").endRule()
                .build()).create();

        roleBindingObj = client.resource(new RoleBindingBuilder()
                .withNewMetadata().withName(ROLE_BINDING).withNamespace(ns)
                .addToLabels(MANAGED_LABEL, MANAGED_VALUE)
                .endMetadata()
                .withNewRoleRef().withApiGroup("rbac.authorization.k8s.io").withKind("Role").withName(ROLE).endRoleRef()
                .addNewSubject().withKind("ServiceAccount").withName(SA).withNamespace(ns).endSubject()
                .build()).create();

        clusterRoleBindingObj = client.resource(new ClusterRoleBindingBuilder()
                .withNewMetadata().withName(clusterRoleBindingName)
                .addToLabels(MANAGED_LABEL, MANAGED_VALUE)
                .endMetadata()
                .withNewRoleRef().withApiGroup("rbac.authorization.k8s.io").withKind("ClusterRole")
                .withName(clusterRoleName).endRoleRef()
                .addNewSubject().withKind("ServiceAccount").withName(SA).withNamespace(ns).endSubject()
                .build()).create();

        secretObj = client.resource(new SecretBuilder()
                .withNewMetadata().withName(SECRET).withNamespace(ns)
                .addToLabels("sensitive", "true")
                .addToLabels(MANAGED_LABEL, MANAGED_VALUE)
                .addToAnnotations(ANNOTATION_KEY, ANNOTATION_VALUE)
                .endMetadata()
                .withType("Opaque")
                .addToStringData("password", DUMMY_SECRET_VALUE)
                .build()).create();

        configMapObj = client.resource(new ConfigMapBuilder()
                .withNewMetadata().withName(CONFIG_MAP).withNamespace(ns)
                .addToLabels(MANAGED_LABEL, MANAGED_VALUE)
                .endMetadata()
                .addToData("key1", "value1")
                .addToData("key2", "value2")
                .build()).create();

        // For the partial-failure test: may list namespaces, nothing else.
        client.resource(new ClusterRoleBuilder()
                .withNewMetadata().withName(nsListerRoleName)
                .addToLabels(MANAGED_LABEL, MANAGED_VALUE)
                .endMetadata()
                .addNewRule().withApiGroups("").withResources("namespaces").withVerbs("get", "list").endRule()
                .build()).create();

        client.resource(new ClusterRoleBindingBuilder()
                .withNewMetadata().withName(nsListerBindingName)
                .addToLabels(MANAGED_LABEL, MANAGED_VALUE)
                .endMetadata()
                .withNewRoleRef().withApiGroup("rbac.authorization.k8s.io").withKind("ClusterRole")
                .withName(nsListerRoleName).endRoleRef()
                .addNewSubject().withKind("ServiceAccount").withName("attackpath-nslister").withNamespace(ns)
                .endSubject()
                .build()).create();
    }

    private static Namespace namespace(String name) {
        return new NamespaceBuilder()
                .withNewMetadata().withName(name)
                .addToLabels(MANAGED_LABEL, MANAGED_VALUE)
                .addToAnnotations(ANNOTATION_KEY, ANNOTATION_VALUE)
                .endMetadata()
                .build();
    }

    // ------------------------------------------------------------------
    // cleanup (only objects carrying the managed label)
    // ------------------------------------------------------------------

    void cleanup() {
        deleteManagedNamespace(ns);
        deleteManagedNamespace(emptyNs);

        for (String name : new String[]{clusterRoleBindingName, nsListerBindingName}) {
            ClusterRoleBinding crb = client.rbac().clusterRoleBindings().withName(name).get();
            if (crb != null && isManaged(crb)) {
                client.rbac().clusterRoleBindings().withName(name).delete();
            }
        }
        for (String name : new String[]{clusterRoleName, nsListerRoleName}) {
            ClusterRole cr = client.rbac().clusterRoles().withName(name).get();
            if (cr != null && isManaged(cr)) {
                client.rbac().clusterRoles().withName(name).delete();
            }
        }

        waitForNamespaceGone(ns);
        waitForNamespaceGone(emptyNs);
    }

    private void deleteManagedNamespace(String name) {
        Namespace existing = client.namespaces().withName(name).get();
        if (existing != null && isManaged(existing)) {
            client.namespaces().withName(name).delete();
        }
    }

    private void waitForNamespaceGone(String name) {
        long deadline = System.currentTimeMillis() + 180_000;
        while (System.currentTimeMillis() < deadline) {
            Namespace n = client.namespaces().withName(name).get();
            if (n == null || !isManaged(n)) {
                return;
            }
            sleep(1000);
        }
        throw new IllegalStateException("Timed out waiting for namespace '" + name + "' to be deleted");
    }

    // ------------------------------------------------------------------
    // special clients
    // ------------------------------------------------------------------

    /** Same connection settings as the real client, but acting as another user (impersonation). */
    KubernetesClient impersonatedClient(String username) {
        Config cfg = new ConfigBuilder(client.getConfiguration())
                .withImpersonateUsername(username)
                .build();
        return new KubernetesClientBuilder().withConfig(cfg).build();
    }

    /** A client pointing at a port nothing listens on; fails fast. */
    static KubernetesClient unreachableClient() {
        Config cfg = new ConfigBuilder(Config.empty())
                .withMasterUrl("https://127.0.0.1:1")
                .withTrustCerts(true)
                .withConnectionTimeout(2000)
                .withRequestTimeout(3000)
                .withRequestRetryBackoffLimit(0)
                .build();
        return new KubernetesClientBuilder().withConfig(cfg).build();
    }

    /** RBAC changes can take a moment to be visible; poll until the namespace list is allowed. */
    static void waitUntilNamespacesListable(KubernetesClient c) {
        long deadline = System.currentTimeMillis() + 30_000;
        KubernetesClientException last = null;
        while (System.currentTimeMillis() < deadline) {
            try {
                c.namespaces().list();
                return;
            } catch (KubernetesClientException e) {
                last = e;
                sleep(500);
            }
        }
        throw new IllegalStateException("Impersonated user never became authorized to list namespaces", last);
    }

    private static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted", e);
        }
    }
}