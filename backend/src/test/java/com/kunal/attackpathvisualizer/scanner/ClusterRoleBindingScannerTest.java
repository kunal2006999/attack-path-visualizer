package com.kunal.attackpathvisualizer.scanner;

import com.kunal.attackpathvisualizer.common.model.snapshot.ClusterRoleBindingSnapshot;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Tag;

@Tag("integration")
public class ClusterRoleBindingScannerTest {

    private static KubernetesClient client;
    private static ClusterRoleBindingScanner scanner;

    @BeforeAll
    static void setUp() {
        client = new KubernetesClientBuilder().build();
        scanner = new ClusterRoleBindingScanner(client);
    }

    @AfterAll
    static void tearDown() {
        if (client != null) {
            client.close();
        }
    }

    @Test
    void scanReturnsNonEmptyListFromRealCluster() {
        List<ClusterRoleBindingSnapshot> snapshots = scanner.scan();

        assertNotNull(snapshots, "scan() must never return null");
        assertFalse(snapshots.isEmpty(), "Expected at least one ClusterRoleBinding from the cluster");
    }

    @Test
    void everySnapshotHasRequiredFields() {
        List<ClusterRoleBindingSnapshot> snapshots = scanner.scan();

        for (ClusterRoleBindingSnapshot snapshot : snapshots) {
            assertNotNull(snapshot.getUid(), "uid must be populated from metadata");
            assertNotNull(snapshot.getName(), "name must be populated from metadata");
            assertNotNull(snapshot.getLabels(), "labels should fall back to empty map, never null");
            assertNotNull(snapshot.getAnnotations(), "annotations should fall back to empty map, never null");
            assertNotNull(snapshot.getCreationTimestamp(), "creationTimestamp must be parsed");
            assertNotNull(snapshot.getClusterRoleName(), "clusterRoleName must be populated from roleRef");
            assertNotNull(snapshot.getSubjectNames(), "subjectNames list should never be null");
        }
    }

    @Test
    void clusterRoleBindingsAreClusterScoped() {
        List<ClusterRoleBindingSnapshot> snapshots = scanner.scan();

        // ClusterRoleBindings are cluster-scoped; namespace field must be null
        for (ClusterRoleBindingSnapshot snapshot : snapshots) {
            assertNull(snapshot.getNamespace(),
                    "ClusterRoleBinding '" + snapshot.getName() + "' must have a null namespace — it is cluster-scoped");
        }
    }

    @Test
    void wellKnownClusterAdminBindingExists() {
        ClusterRoleBindingSnapshot clusterAdminBinding =
                findByName(scanner.scan(), "cluster-admin");

        assertNotNull(clusterAdminBinding,
                "Expected to find a 'cluster-admin' ClusterRoleBinding on the cluster");
        assertEquals("cluster-admin", clusterAdminBinding.getName());
        assertNull(clusterAdminBinding.getNamespace());
        assertNotNull(clusterAdminBinding.getUid());
        assertNotNull(clusterAdminBinding.getCreationTimestamp());
        assertEquals("cluster-admin", clusterAdminBinding.getClusterRoleName());
        assertFalse(clusterAdminBinding.getSubjectNames().isEmpty(),
                "cluster-admin binding should have at least one subject");
    }

    private static ClusterRoleBindingSnapshot findByName(
            List<ClusterRoleBindingSnapshot> snapshots, String name) {
        Optional<ClusterRoleBindingSnapshot> match = snapshots.stream()
                .filter(crb -> name.equals(crb.getName()))
                .findFirst();
        return match.orElse(null);
    }
}
