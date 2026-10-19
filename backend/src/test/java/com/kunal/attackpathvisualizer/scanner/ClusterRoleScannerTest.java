package com.kunal.attackpathvisualizer.scanner;

import com.kunal.attackpathvisualizer.common.model.snapshot.ClusterRoleSnapshot;
import com.kunal.attackpathvisualizer.common.model.snapshot.RbacRuleSnapshot;
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
public class ClusterRoleScannerTest {

    private static KubernetesClient client;
    private static ClusterRoleScanner scanner;

    @BeforeAll
    static void setUp() {
        client = new KubernetesClientBuilder().build();
        scanner = new ClusterRoleScanner(client);
    }

    @AfterAll
    static void tearDown() {
        if (client != null) {
            client.close();
        }
    }

    @Test
    void scanReturnsNonEmptyListFromRealCluster() {
        List<ClusterRoleSnapshot> snapshots = scanner.scan();

        assertNotNull(snapshots, "scan() must never return null");
        assertFalse(snapshots.isEmpty(), "Expected at least one ClusterRole from the cluster");
    }

    @Test
    void everySnapshotHasRequiredFields() {
        List<ClusterRoleSnapshot> snapshots = scanner.scan();

        for (ClusterRoleSnapshot snapshot : snapshots) {
            assertNotNull(snapshot.getUid(), "uid must be populated from metadata");
            assertNotNull(snapshot.getName(), "name must be populated from metadata");
            assertNotNull(snapshot.getLabels(), "labels should fall back to empty map, never null");
            assertNotNull(snapshot.getAnnotations(), "annotations should fall back to empty map, never null");
            assertNotNull(snapshot.getCreationTimestamp(), "creationTimestamp must be parsed");
            assertNotNull(snapshot.getRules(), "rules list should never be null");
        }
    }

    @Test
    void clusterRolesAreClusterScoped() {
        List<ClusterRoleSnapshot> snapshots = scanner.scan();

        // ClusterRoles are cluster-scoped; namespace field must be null
        for (ClusterRoleSnapshot snapshot : snapshots) {
            assertNull(snapshot.getNamespace(),
                    "ClusterRole '" + snapshot.getName() + "' must have a null namespace — it is cluster-scoped");
        }
    }

    @Test
    void wellKnownClusterRoleClusterAdminExists() {
        ClusterRoleSnapshot clusterAdmin = findByName(scanner.scan(), "cluster-admin");

        assertNotNull(clusterAdmin, "Expected to find 'cluster-admin' ClusterRole on the cluster");
        assertEquals("cluster-admin", clusterAdmin.getName());
        assertNotNull(clusterAdmin.getUid());
        assertNotNull(clusterAdmin.getCreationTimestamp());
        assertNull(clusterAdmin.getNamespace());
    }

    @Test
    void everyRuleHasNonNullLists() {
        List<ClusterRoleSnapshot> snapshots = scanner.scan();

        for (ClusterRoleSnapshot snapshot : snapshots) {
            for (RbacRuleSnapshot rule : snapshot.getRules()) {
                assertNotNull(rule.getApiGroups(), "apiGroups must not be null");
                assertNotNull(rule.getResources(), "resources must not be null");
                assertNotNull(rule.getVerbs(), "verbs must not be null");
                assertNotNull(rule.getResourceNames(), "resourceNames must not be null");
            }
        }
    }

    private static ClusterRoleSnapshot findByName(List<ClusterRoleSnapshot> snapshots, String name) {
        Optional<ClusterRoleSnapshot> match = snapshots.stream()
                .filter(cr -> name.equals(cr.getName()))
                .findFirst();
        return match.orElse(null);
    }
}
