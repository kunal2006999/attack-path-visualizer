package com.kunal.attackpathvisualizer.scanner;

import com.kunal.attackpathvisualizer.common.model.snapshot.ClusterSnapshot;
import io.fabric8.kubernetes.client.KubernetesClient;

import java.util.Collections;

/**
 * Assembles a complete {@link ClusterSnapshot} by running all 10 resource scanners
 * against a live Kubernetes cluster.
 *
 * <h3>Failure semantics</h3>
 * <p>If any scanner fails (Kubernetes API error, timeout, RBAC denial, malformed response,
 * unparseable timestamp), this assembler rethrows the {@link ScannerException} immediately.
 * <strong>No partial snapshot is silently returned.</strong>
 *
 * <p>Callers must not treat a {@link ScannerException} as an empty successful scan.
 * The exception carries the {@link ScannerException#getResourceCategory() resource category}
 * that failed, together with the original cause, so callers can surface a clear error.
 */
public class ClusterSnapshotAssembler {

    private final String clusterName;

    private final NamespaceScanner namespaceScanner;
    private final PodScanner podScanner;
    private final ServiceScanner serviceScanner;
    private final ServiceAccountScanner serviceAccountScanner;

    private final RoleScanner roleScanner;
    private final ClusterRoleScanner clusterRoleScanner;
    private final RoleBindingScanner roleBindingScanner;
    private final ClusterRoleBindingScanner clusterRoleBindingScanner;

    private final SecretScanner secretScanner;
    private final ConfigMapScanner configMapScanner;


    public ClusterSnapshotAssembler(KubernetesClient client, String clusterName) {

        if (client == null) {
            throw new IllegalArgumentException(
                    "KubernetesClient cannot be null");
        }
        if (clusterName == null || clusterName.isBlank()) {
            throw new IllegalArgumentException(
                    "Cluster name cannot be null or blank");
        }

        this.clusterName = clusterName;
        this.namespaceScanner = new NamespaceScanner(client);
        this.podScanner = new PodScanner(client);
        this.serviceScanner = new ServiceScanner(client);
        this.serviceAccountScanner = new ServiceAccountScanner(client);
        this.roleScanner = new RoleScanner(client);
        this.clusterRoleScanner = new ClusterRoleScanner(client);
        this.roleBindingScanner = new RoleBindingScanner(client);
        this.clusterRoleBindingScanner = new ClusterRoleBindingScanner(client);
        this.secretScanner = new SecretScanner(client);
        this.configMapScanner = new ConfigMapScanner(client);
    }

    /**
     * Runs all resource scanners and assembles the results into a {@link ClusterSnapshot}.
     *
     * <p>Every scanner is called in sequence. If any scanner throws a {@link ScannerException}
     * the exception propagates immediately — no subsequent scanners are run, and no partial
     * snapshot is returned. This prevents a degraded scan from being treated as a complete,
     * authoritative result by downstream pipeline stages.
     *
     * @return a fully populated snapshot representing the cluster state at the time of the scan
     * @throws ScannerException if any resource category cannot be retrieved from the API server
     */
    public ClusterSnapshot scanCluster() {

        ClusterSnapshot snapshot = new ClusterSnapshot();
        snapshot.setClusterName(clusterName);

        // Each call below may throw ScannerException.  Do not catch and swallow it here —
        // let it propagate so the caller can distinguish a failed scan from an empty one.

        snapshot.setNamespaces(namespaceScanner.scan());
        snapshot.setPods(podScanner.scan());
        snapshot.setServices(serviceScanner.scan());
        snapshot.setServiceAccounts(serviceAccountScanner.scan());
        snapshot.setRoles(roleScanner.scan());
        snapshot.setClusterRoles(clusterRoleScanner.scan());
        snapshot.setRoleBindings(roleBindingScanner.scan());
        snapshot.setClusterRoleBindings(clusterRoleBindingScanner.scan());
        snapshot.setSecrets(secretScanner.scan());
        snapshot.setConfigMaps(configMapScanner.scan());

        // These resource categories are not yet scanned.
        snapshot.setNodes(Collections.emptyList());
        snapshot.setDeployments(Collections.emptyList());
        snapshot.setReplicaSets(Collections.emptyList());
        snapshot.setIngresses(Collections.emptyList());
        snapshot.setPersistentVolumes(Collections.emptyList());
        snapshot.setPersistentVolumeClaims(Collections.emptyList());

        return snapshot;
    }
}
