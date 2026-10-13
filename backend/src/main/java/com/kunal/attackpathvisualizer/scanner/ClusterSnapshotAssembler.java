package com.kunal.attackpathvisualizer.scanner;

import com.kunal.attackpathvisualizer.common.model.snapshot.ClusterSnapshot;
import io.fabric8.kubernetes.client.KubernetesClient;

import java.util.Collections;
import java.util.List;

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

    public ClusterSnapshot scanCluster() {

        ClusterSnapshot snapshot = new ClusterSnapshot();

        snapshot.setClusterName(clusterName);

        // Scan the ten supported resource categories.
        snapshot.setNamespaces(
                safeList(namespaceScanner.scan()));

        snapshot.setPods(
                safeList(podScanner.scan()));

        snapshot.setServices(
                safeList(serviceScanner.scan()));

        snapshot.setServiceAccounts(
                safeList(serviceAccountScanner.scan()));

        snapshot.setRoles(
                safeList(roleScanner.scan()));

        snapshot.setClusterRoles(
                safeList(clusterRoleScanner.scan()));

        snapshot.setRoleBindings(
                safeList(roleBindingScanner.scan()));

        snapshot.setClusterRoleBindings(
                safeList(clusterRoleBindingScanner.scan()));

        snapshot.setSecrets(
                safeList(secretScanner.scan()));

        snapshot.setConfigMaps(
                safeList(configMapScanner.scan()));

        // These resource categories are not yet scanned.
        snapshot.setNodes(Collections.emptyList());
        snapshot.setDeployments(Collections.emptyList());
        snapshot.setReplicaSets(Collections.emptyList());
        snapshot.setIngresses(Collections.emptyList());
        snapshot.setPersistentVolumes(Collections.emptyList());
        snapshot.setPersistentVolumeClaims(Collections.emptyList());

        return snapshot;
    }

    private <T> List<T> safeList(List<T> list) {
        return list != null ? list : Collections.emptyList();
    }
}
