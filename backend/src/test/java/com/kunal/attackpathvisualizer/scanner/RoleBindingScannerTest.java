package com.kunal.attackpathvisualizer.scanner;

import com.kunal.attackpathvisualizer.common.model.snapshot.RoleBindingSnapshot;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class RoleBindingScannerTest {

    private static KubernetesClient client;
    private static RoleBindingScanner scanner;

    @BeforeAll
    static void setUp() {
        client = new KubernetesClientBuilder().build();
        scanner = new RoleBindingScanner(client);
    }

    @AfterAll
    static void tearDown() {
        if (client != null) {
            client.close();
        }
    }

    @Test
    void scanReturnsNonNullList() {
        List<RoleBindingSnapshot> snapshots = scanner.scan();

        assertNotNull(snapshots, "scan() must never return null");
    }

    @Test
    void everySnapshotHasRequiredFields() {
        List<RoleBindingSnapshot> snapshots = scanner.scan();

        for (RoleBindingSnapshot snapshot : snapshots) {
            assertNotNull(snapshot.getUid(), "uid must be populated from metadata");
            assertNotNull(snapshot.getName(), "name must be populated from metadata");
            assertNotNull(snapshot.getNamespace(), "namespace must be populated — RoleBindings are namespace-scoped");
            assertNotNull(snapshot.getLabels(), "labels should fall back to empty map, never null");
            assertNotNull(snapshot.getAnnotations(), "annotations should fall back to empty map, never null");
            assertNotNull(snapshot.getCreationTimestamp(), "creationTimestamp must be parsed");
            assertNotNull(snapshot.getRoleName(), "roleName must be populated from roleRef");
            assertNotNull(snapshot.getSubjectNames(), "subjectNames list should never be null");
        }
    }

    @Test
    void allSnapshotsAreNamespaceScoped() {
        List<RoleBindingSnapshot> snapshots = scanner.scan();

        for (RoleBindingSnapshot snapshot : snapshots) {
            assertNotNull(snapshot.getNamespace(),
                    "RoleBinding '" + snapshot.getName() + "' must have a non-null namespace");
        }
    }

    @Test
    void subjectNamesListIsNeverNull() {
        List<RoleBindingSnapshot> snapshots = scanner.scan();

        for (RoleBindingSnapshot snapshot : snapshots) {
            assertNotNull(snapshot.getSubjectNames(),
                    "subjectNames must not be null for RoleBinding '" + snapshot.getName() + "'");
        }
    }
}
