package com.kunal.attackpathvisualizer.integration;

import com.kunal.attackpathvisualizer.common.model.snapshot.ClusterRoleBindingSnapshot;
import com.kunal.attackpathvisualizer.common.model.snapshot.ClusterRoleSnapshot;
import com.kunal.attackpathvisualizer.common.model.snapshot.ClusterSnapshot;
import com.kunal.attackpathvisualizer.common.model.snapshot.ConfigMapSnapshot;
import com.kunal.attackpathvisualizer.common.model.snapshot.NamespaceSnapshot;
import com.kunal.attackpathvisualizer.common.model.snapshot.PodSnapshot;
import com.kunal.attackpathvisualizer.common.model.snapshot.RbacRuleSnapshot;
import com.kunal.attackpathvisualizer.common.model.snapshot.ResourceSnapshot;
import com.kunal.attackpathvisualizer.common.model.snapshot.RoleBindingSnapshot;
import com.kunal.attackpathvisualizer.common.model.snapshot.RoleSnapshot;
import com.kunal.attackpathvisualizer.common.model.snapshot.SecretSnapshot;
import com.kunal.attackpathvisualizer.common.model.snapshot.ServiceAccountSnapshot;
import com.kunal.attackpathvisualizer.common.model.snapshot.ServiceSnapshot;
import com.kunal.attackpathvisualizer.common.model.snapshot.SubjectSnapshot;
import com.kunal.attackpathvisualizer.common.util.ClusterSnapshotParser;
import com.kunal.attackpathvisualizer.core.builder.ClusterSnapshotMapper;
import com.kunal.attackpathvisualizer.core.pipeline.ClusterGraphPipeline;
import com.kunal.attackpathvisualizer.core.validation.ClusterSnapshotValidator;
import com.kunal.attackpathvisualizer.graph.GraphBuilder;
import com.kunal.attackpathvisualizer.scanner.ClusterRoleBindingScanner;
import com.kunal.attackpathvisualizer.scanner.ClusterRoleScanner;
import com.kunal.attackpathvisualizer.scanner.ClusterSnapshotAssembler;
import com.kunal.attackpathvisualizer.scanner.ConfigMapScanner;
import com.kunal.attackpathvisualizer.scanner.NamespaceScanner;
import com.kunal.attackpathvisualizer.scanner.PodScanner;
import com.kunal.attackpathvisualizer.scanner.RoleBindingScanner;
import com.kunal.attackpathvisualizer.scanner.RoleScanner;
import com.kunal.attackpathvisualizer.scanner.ScannerException;
import com.kunal.attackpathvisualizer.scanner.SecretScanner;
import com.kunal.attackpathvisualizer.scanner.ServiceAccountScanner;
import com.kunal.attackpathvisualizer.scanner.ServiceScanner;
import io.fabric8.kubernetes.api.model.HasMetadata;
import io.fabric8.kubernetes.api.model.ObjectMeta;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Live tests of the ten scanners, ClusterSnapshotAssembler, and scanner failure handling
 * against a real Minikube API server. Run only with -Pintegration.
 */
@Tag("integration")
class LiveScannerIntegrationTest {

    private static final String NS = "attackpath-test";

    private static LiveClusterFixture fx;

    @BeforeAll
    static void setUp() {
        fx = new LiveClusterFixture(NS);
        fx.setUp();
    }

    @AfterAll
    static void tearDown() {
        if (fx != null) {
            fx.close();
        }
    }

    // ------------------------------------------------------------------
    // one test per scanner
    // ------------------------------------------------------------------

    @Test
    void namespaceScanner() {
        assertNamespaces(new NamespaceScanner(fx.client).scan());
    }

    @Test
    void podScanner() {
        assertPods(new PodScanner(fx.client).scan());
    }

    @Test
    void serviceScanner() {
        assertServices(new ServiceScanner(fx.client).scan());
    }

    @Test
    void serviceAccountScanner() {
        assertServiceAccounts(new ServiceAccountScanner(fx.client).scan());
    }

    @Test
    void roleScanner() {
        assertRoles(new RoleScanner(fx.client).scan());
    }

    @Test
    void clusterRoleScanner() {
        assertClusterRoles(new ClusterRoleScanner(fx.client).scan());
    }

    @Test
    void roleBindingScanner() {
        assertRoleBindings(new RoleBindingScanner(fx.client).scan());
    }

    @Test
    void clusterRoleBindingScanner() {
        assertClusterRoleBindings(new ClusterRoleBindingScanner(fx.client).scan());
    }

    @Test
    void secretScanner() {
        List<SecretSnapshot> all = new SecretScanner(fx.client).scan();
        assertSecrets(all);

        // Secret data must never be captured.
        assertTrue(Arrays.stream(SecretSnapshot.class.getDeclaredFields())
                .noneMatch(f -> f.getName().toLowerCase().contains("data")));
        SecretSnapshot ours = single(inNs(all, NS), s -> LiveClusterFixture.SECRET.equals(s.getName()), "test Secret");
        String json = new ObjectMapper().writeValueAsString(ours);
        assertFalse(json.contains(LiveClusterFixture.DUMMY_SECRET_VALUE));
    }

    @Test
    void configMapScanner() {
        assertConfigMaps(new ConfigMapScanner(fx.client).scan());
    }

    // ------------------------------------------------------------------
    // empty namespace
    // ------------------------------------------------------------------

    @Test
    void emptyNamespaceHasNoUserResources() {
        String empty = fx.emptyNs;
        KubernetesClient c = fx.client;

        assertTrue(new NamespaceScanner(c).scan().stream().anyMatch(n -> empty.equals(n.getName())));

        assertEquals(0, inNs(new PodScanner(c).scan(), empty).size());
        assertEquals(0, inNs(new ServiceScanner(c).scan(), empty).size());
        assertEquals(0, inNs(new RoleScanner(c).scan(), empty).size());
        assertEquals(0, inNs(new RoleBindingScanner(c).scan(), empty).size());

        // Only Kubernetes-managed objects may exist.
        for (ServiceAccountSnapshot sa : inNs(new ServiceAccountScanner(c).scan(), empty)) {
            assertEquals("default", sa.getName());
        }
        for (ConfigMapSnapshot cm : inNs(new ConfigMapScanner(c).scan(), empty)) {
            assertEquals("kube-root-ca.crt", cm.getName());
        }
        for (SecretSnapshot s : inNs(new SecretScanner(c).scan(), empty)) {
            assertEquals(LiveClusterFixture.SA_TOKEN_TYPE, s.getSecretType());
        }
    }

    // ------------------------------------------------------------------
    // assembler
    // ------------------------------------------------------------------

    @Test
    void assemblerProducesCompleteSnapshot() {
        ClusterSnapshot snap = new ClusterSnapshotAssembler(fx.client, "minikube-it").scanCluster();

        assertEquals("minikube-it", snap.getClusterName());
        assertNotNull(snap.getNodes());
        assertNotNull(snap.getDeployments());
        assertNotNull(snap.getReplicaSets());
        assertNotNull(snap.getIngresses());
        assertNotNull(snap.getPersistentVolumes());
        assertNotNull(snap.getPersistentVolumeClaims());

        assertNamespaces(snap.getNamespaces());
        assertPods(snap.getPods());
        assertServices(snap.getServices());
        assertServiceAccounts(snap.getServiceAccounts());
        assertRoles(snap.getRoles());
        assertClusterRoles(snap.getClusterRoles());
        assertRoleBindings(snap.getRoleBindings());
        assertClusterRoleBindings(snap.getClusterRoleBindings());
        assertSecrets(snap.getSecrets());
        assertConfigMaps(snap.getConfigMaps());

        // A live snapshot must satisfy the validator (unique UIDs, names present).
        assertDoesNotThrow(() -> new ClusterSnapshotValidator().validate(snap));
    }

    // ------------------------------------------------------------------
    // failure handling
    // ------------------------------------------------------------------

    @Test
    void unreachableApiFailsLoudly() {
        try (KubernetesClient bad = LiveClusterFixture.unreachableClient()) {
            ScannerException ex = assertThrows(ScannerException.class,
                    () -> new NamespaceScanner(bad).scan());
            assertEquals("Namespaces", ex.getResourceCategory());
            assertInstanceOf(KubernetesClientException.class, ex.getCause());

            assertThrows(ScannerException.class,
                    () -> new ClusterSnapshotAssembler(bad, "x").scanCluster());
            assertThrows(ScannerException.class,
                    () -> pipeline().buildFromLiveCluster(bad, "x"));
        }
    }

    @Test
    void insufficientPermissionsFailLoudlyWith403() {
        try (KubernetesClient denied = fx.impersonatedClient(fx.deniedUser())) {
            ScannerException ex = assertThrows(ScannerException.class,
                    () -> new NamespaceScanner(denied).scan());
            assertEquals("Namespaces", ex.getResourceCategory());
            KubernetesClientException cause =
                    assertInstanceOf(KubernetesClientException.class, ex.getCause());
            assertEquals(403, cause.getCode());

            ScannerException podEx = assertThrows(ScannerException.class,
                    () -> new PodScanner(denied).scan());
            assertEquals("Pods", podEx.getResourceCategory());

            assertThrows(ScannerException.class,
                    () -> new ClusterSnapshotAssembler(denied, "x").scanCluster());
            assertThrows(ScannerException.class,
                    () -> pipeline().buildFromLiveCluster(denied, "x"));
        }
    }

    @Test
    void partialFailureDoesNotYieldPartialSnapshot() {
        // This identity may list namespaces (first scanner) but nothing else.
        try (KubernetesClient partial = fx.impersonatedClient(fx.nsListerUser())) {
            LiveClusterFixture.waitUntilNamespacesListable(partial);

            assertFalse(new NamespaceScanner(partial).scan().isEmpty());

            ScannerException ex = assertThrows(ScannerException.class,
                    () -> new ClusterSnapshotAssembler(partial, "x").scanCluster());
            assertEquals("Pods", ex.getResourceCategory());

            assertThrows(ScannerException.class,
                    () -> pipeline().buildFromLiveCluster(partial, "x"));
        }
    }

    // ------------------------------------------------------------------
    // per-resource assertions (shared by scanner tests and assembler test)
    // ------------------------------------------------------------------

    private static void assertNamespaces(List<NamespaceSnapshot> all) {
        NamespaceSnapshot ours = single(all, n -> NS.equals(n.getName()), "test namespace");
        assertMetadata(fx.namespaceObj, ours, null);
        assertEquals(LiveClusterFixture.MANAGED_VALUE, ours.getLabels().get(LiveClusterFixture.MANAGED_LABEL));

        NamespaceSnapshot empty = single(all, n -> fx.emptyNs.equals(n.getName()), "empty namespace");
        assertMetadata(fx.emptyNamespaceObj, empty, null);

        assertTrue(all.stream().anyMatch(n -> "default".equals(n.getName())));
        assertTrue(all.stream().anyMatch(n -> "kube-system".equals(n.getName())));
    }

    private static void assertPods(List<PodSnapshot> all) {
        List<PodSnapshot> mine = inNs(all, NS);
        assertEquals(1, mine.size());
        PodSnapshot p = mine.get(0);
        assertEquals(LiveClusterFixture.POD, p.getName());
        assertMetadata(fx.podObj, p, NS);
        assertEquals(LiveClusterFixture.SA, p.getServiceAccountName());
        assertEquals("backend", p.getLabels().get("app"));
    }

    private static void assertServices(List<ServiceSnapshot> all) {
        List<ServiceSnapshot> mine = inNs(all, NS);
        assertEquals(1, mine.size());
        ServiceSnapshot s = mine.get(0);
        assertEquals(LiveClusterFixture.SERVICE, s.getName());
        assertMetadata(fx.serviceObj, s, NS);
        assertEquals(Map.of("app", "backend"), s.getSelector());
    }

    private static void assertServiceAccounts(List<ServiceAccountSnapshot> all) {
        List<ServiceAccountSnapshot> mine = inNs(all, NS);
        ServiceAccountSnapshot sa = single(mine, s -> LiveClusterFixture.SA.equals(s.getName()), "test ServiceAccount");
        assertMetadata(fx.serviceAccountObj, sa, NS);
        assertOnlyAllowed(mine, LiveClusterFixture.SA, Set.of("default"));
    }

    private static void assertRoles(List<RoleSnapshot> all) {
        List<RoleSnapshot> mine = inNs(all, NS);
        assertEquals(1, mine.size());
        RoleSnapshot r = mine.get(0);
        assertEquals(LiveClusterFixture.ROLE, r.getName());
        assertMetadata(fx.roleObj, r, NS);
        assertSingleRule(r.getRules(), "secrets");
    }

    private static void assertClusterRoles(List<ClusterRoleSnapshot> all) {
        ClusterRoleSnapshot r = single(all, c -> fx.clusterRoleName.equals(c.getName()), "test ClusterRole");
        assertMetadata(fx.clusterRoleObj, r, null);
        assertSingleRule(r.getRules(), "namespaces");
    }

    private static void assertRoleBindings(List<RoleBindingSnapshot> all) {
        List<RoleBindingSnapshot> mine = inNs(all, NS);
        assertEquals(1, mine.size());
        RoleBindingSnapshot rb = mine.get(0);
        assertEquals(LiveClusterFixture.ROLE_BINDING, rb.getName());
        assertMetadata(fx.roleBindingObj, rb, NS);
        assertEquals(LiveClusterFixture.ROLE, rb.getRoleName());
        assertEquals("Role", rb.getRoleKind());
        assertEquals(List.of(LiveClusterFixture.SA), rb.getSubjectNames());
        assertSingleSaSubject(rb.getSubjects());
    }

    private static void assertClusterRoleBindings(List<ClusterRoleBindingSnapshot> all) {
        ClusterRoleBindingSnapshot crb = single(all,
                c -> fx.clusterRoleBindingName.equals(c.getName()), "test ClusterRoleBinding");
        assertMetadata(fx.clusterRoleBindingObj, crb, null);
        assertEquals(fx.clusterRoleName, crb.getClusterRoleName());
        assertEquals(List.of(LiveClusterFixture.SA), crb.getSubjectNames());
        assertSingleSaSubject(crb.getSubjects());
    }

    private static void assertSecrets(List<SecretSnapshot> all) {
        List<SecretSnapshot> mine = inNs(all, NS);
        SecretSnapshot s = single(mine, x -> LiveClusterFixture.SECRET.equals(x.getName()), "test Secret");
        assertMetadata(fx.secretObj, s, NS);
        assertEquals("Opaque", s.getSecretType());
        assertEquals("true", s.getLabels().get("sensitive"));
        for (SecretSnapshot other : mine) {
            if (other != s) {
                assertEquals(LiveClusterFixture.SA_TOKEN_TYPE, other.getSecretType());
            }
        }
    }

    private static void assertConfigMaps(List<ConfigMapSnapshot> all) {
        List<ConfigMapSnapshot> mine = inNs(all, NS);
        ConfigMapSnapshot cm = single(mine, c -> LiveClusterFixture.CONFIG_MAP.equals(c.getName()), "test ConfigMap");
        assertMetadata(fx.configMapObj, cm, NS);
        assertOnlyAllowed(mine, LiveClusterFixture.CONFIG_MAP, Set.of("kube-root-ca.crt"));
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    private static void assertMetadata(HasMetadata expected, ResourceSnapshot actual, String expectedNamespace) {
        ObjectMeta m = expected.getMetadata();
        assertEquals(m.getUid(), actual.getUid(), "uid");
        assertEquals(m.getName(), actual.getName(), "name");
        assertEquals(expectedNamespace, actual.getNamespace(), "namespace");
        assertNotNull(actual.getLabels());
        assertNotNull(actual.getAnnotations());
        if (m.getLabels() != null) {
            m.getLabels().forEach((k, v) -> assertEquals(v, actual.getLabels().get(k), "label " + k));
        }
        if (m.getAnnotations() != null) {
            m.getAnnotations().forEach((k, v) ->
                    assertEquals(v, actual.getAnnotations().get(k), "annotation " + k));
        }
        assertEquals(Instant.parse(m.getCreationTimestamp()), actual.getCreationTimestamp(), "creationTimestamp");
    }

    private static void assertSingleRule(List<RbacRuleSnapshot> rules, String resource) {
        assertNotNull(rules);
        assertEquals(1, rules.size());
        RbacRuleSnapshot r = rules.get(0);
        assertEquals(List.of(""), r.getApiGroups());
        assertEquals(List.of(resource), r.getResources());
        assertEquals(List.of("get", "list"), r.getVerbs());
        assertNotNull(r.getResourceNames());
        assertTrue(r.getResourceNames().isEmpty());
    }

    private static void assertSingleSaSubject(List<SubjectSnapshot> subjects) {
        assertNotNull(subjects);
        assertEquals(1, subjects.size());
        assertEquals("ServiceAccount", subjects.get(0).getKind());
        assertEquals(LiveClusterFixture.SA, subjects.get(0).getName());
        assertEquals(NS, subjects.get(0).getNamespace());
    }

    private static <T extends ResourceSnapshot> List<T> inNs(List<T> all, String namespace) {
        return all.stream().filter(r -> namespace.equals(r.getNamespace())).toList();
    }

    private static <T> T single(List<T> list, Predicate<T> predicate, String what) {
        List<T> matches = list.stream().filter(predicate).toList();
        assertEquals(1, matches.size(), "Expected exactly one " + what + " but found " + matches.size());
        return matches.get(0);
    }

    private static void assertOnlyAllowed(List<? extends ResourceSnapshot> mine, String ourName, Set<String> allowed) {
        for (ResourceSnapshot r : mine) {
            if (!ourName.equals(r.getName())) {
                assertTrue(allowed.contains(r.getName()),
                        "Unexpected resource '" + r.getName() + "' in namespace " + r.getNamespace());
            }
        }
    }

    private static ClusterGraphPipeline pipeline() {
        return new ClusterGraphPipeline(
                new ClusterSnapshotParser(),
                new ClusterSnapshotValidator(),
                new ClusterSnapshotMapper(),
                new GraphBuilder());
    }
}