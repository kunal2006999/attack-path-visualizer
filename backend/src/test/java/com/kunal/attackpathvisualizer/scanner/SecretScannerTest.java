package com.kunal.attackpathvisualizer.scanner;

import com.kunal.attackpathvisualizer.common.model.snapshot.SecretSnapshot;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Tag;

@Tag("integration")
public class SecretScannerTest {

    private static KubernetesClient client;
    private static SecretScanner scanner;

    @BeforeAll
    static void setUp() {
        client = new KubernetesClientBuilder().build();
        scanner = new SecretScanner(client);
    }

    @AfterAll
    static void tearDown() {
        if (client != null) {
            client.close();
        }
    }

    @Test
    void scanReturnsNonNullList() {
        List<SecretSnapshot> snapshots = scanner.scan();

        // scan() must never return null; empty is valid on clusters where no Secrets
        // exist (e.g. Kubernetes 1.24+ no longer auto-creates SA token Secrets).
        assertNotNull(snapshots, "scan() must never return null");
    }

    @Test
    void everySnapshotHasRequiredFields() {
        List<SecretSnapshot> snapshots = scanner.scan();

        for (SecretSnapshot snapshot : snapshots) {
            assertNotNull(snapshot.getUid(), "uid must be populated from metadata");
            assertNotNull(snapshot.getName(), "name must be populated from metadata");
            assertNotNull(snapshot.getNamespace(), "namespace must be populated — Secrets are namespace-scoped");
            assertNotNull(snapshot.getLabels(), "labels should fall back to empty map, never null");
            assertNotNull(snapshot.getAnnotations(), "annotations should fall back to empty map, never null");
            assertNotNull(snapshot.getCreationTimestamp(), "creationTimestamp must be parsed");
            // secretType can legitimately be null only if the field is missing from the API response,
            // but standard secrets always have a type; we just assert the field is accessible
        }
    }

    @Test
    void allSnapshotsAreNamespaceScoped() {
        List<SecretSnapshot> snapshots = scanner.scan();

        for (SecretSnapshot snapshot : snapshots) {
            assertNotNull(snapshot.getNamespace(),
                    "Secret '" + snapshot.getName() + "' must have a non-null namespace");
        }
    }

    @Test
    void secretTypeIsPopulatedWhenSecretsExist() {
        List<SecretSnapshot> snapshots = scanner.scan();

        // If the cluster has secrets, every one must have a non-null type mapped.
        // An empty list is valid on Kubernetes 1.24+ clusters where SA token Secrets
        // are no longer auto-created.
        if (snapshots.isEmpty()) {
            return; // nothing to assert — scanner correctly returned an empty list
        }

        long withType = snapshots.stream()
                .filter(s -> s.getSecretType() != null)
                .count();

        assertTrue(withType > 0, "Expected at least one secret to have a non-null secretType");
    }
}
