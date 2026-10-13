package com.kunal.attackpathvisualizer.scanner;

import com.kunal.attackpathvisualizer.common.model.snapshot.RbacRuleSnapshot;
import com.kunal.attackpathvisualizer.common.model.snapshot.RoleSnapshot;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

public class RoleScannerTest {

    private static KubernetesClient client;
    private static RoleScanner scanner;

    @BeforeAll
    static void setUp() {
        client = new KubernetesClientBuilder().build();
        scanner = new RoleScanner(client);
    }

    @AfterAll
    static void tearDown() {
        if (client != null) {
            client.close();
        }
    }

    @Test
    void scanReturnsNonNullList() {
        List<RoleSnapshot> snapshots = scanner.scan();

        assertNotNull(snapshots, "scan() must never return null");
    }

    @Test
    void everySnapshotHasRequiredFields() {
        List<RoleSnapshot> snapshots = scanner.scan();

        for (RoleSnapshot snapshot : snapshots) {
            assertNotNull(snapshot.getUid(), "uid must be populated from metadata");
            assertNotNull(snapshot.getName(), "name must be populated from metadata");
            assertNotNull(snapshot.getNamespace(), "namespace must be populated — Roles are namespace-scoped");
            assertNotNull(snapshot.getLabels(), "labels should fall back to empty map, never null");
            assertNotNull(snapshot.getAnnotations(), "annotations should fall back to empty map, never null");
            assertNotNull(snapshot.getCreationTimestamp(), "creationTimestamp must be parsed");
            assertNotNull(snapshot.getRules(), "rules list should never be null");
        }
    }

    @Test
    void everyRuleHasNonNullLists() {
        List<RoleSnapshot> snapshots = scanner.scan();

        for (RoleSnapshot snapshot : snapshots) {
            for (RbacRuleSnapshot rule : snapshot.getRules()) {
                assertNotNull(rule.getApiGroups(), "apiGroups must not be null");
                assertNotNull(rule.getResources(), "resources must not be null");
                assertNotNull(rule.getVerbs(), "verbs must not be null");
                assertNotNull(rule.getResourceNames(), "resourceNames must not be null");
            }
        }
    }

    @Test
    void allSnapshotsAreNamespaceScoped() {
        List<RoleSnapshot> snapshots = scanner.scan();

        // Roles are always namespace-scoped; none should have a null namespace
        for (RoleSnapshot snapshot : snapshots) {
            assertNotNull(snapshot.getNamespace(),
                    "Role '" + snapshot.getName() + "' must have a non-null namespace");
        }
    }

    private static Optional<RoleSnapshot> findByNameAndNamespace(
            List<RoleSnapshot> snapshots, String name, String namespace) {
        return snapshots.stream()
                .filter(r -> name.equals(r.getName()) && namespace.equals(r.getNamespace()))
                .findFirst();
    }
}
