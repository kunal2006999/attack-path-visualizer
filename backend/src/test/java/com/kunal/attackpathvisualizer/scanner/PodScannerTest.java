package com.kunal.attackpathvisualizer.scanner;

import com.kunal.attackpathvisualizer.common.model.snapshot.PodSnapshot;
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
public class PodScannerTest {

    private static KubernetesClient client;
    private static PodScanner scanner;

    @BeforeAll
    static void setUp() {
        client = new KubernetesClientBuilder().build();
        scanner = new PodScanner(client);
    }

    @AfterAll
    static void tearDown() {
        if (client != null) {
            client.close();
        }
    }

    @Test
    void scanReturnsNonNullList() {
        List<PodSnapshot> snapshots = scanner.scan();

        assertNotNull(snapshots, "scan() must never return null");
    }

    @Test
    void everySnapshotHasRequiredFields() {
        List<PodSnapshot> snapshots = scanner.scan();

        for (PodSnapshot snapshot : snapshots) {
            assertNotNull(snapshot.getUid(), "uid must be populated from metadata");
            assertNotNull(snapshot.getName(), "name must be populated from metadata");
            assertNotNull(snapshot.getNamespace(), "namespace must be populated — Pods are namespace-scoped");
            assertNotNull(snapshot.getLabels(), "labels should fall back to empty map, never null");
            assertNotNull(snapshot.getAnnotations(), "annotations should fall back to empty map, never null");
            assertNotNull(snapshot.getCreationTimestamp(), "creationTimestamp must be parsed");
            // serviceAccountName may legitimately be null for pods with no explicit SA,
            // but the field itself must be accessible without NPE
        }
    }

    @Test
    void allSnapshotsAreNamespaceScoped() {
        List<PodSnapshot> snapshots = scanner.scan();

        for (PodSnapshot snapshot : snapshots) {
            assertNotNull(snapshot.getNamespace(),
                    "Pod '" + snapshot.getName() + "' must have a non-null namespace");
        }
    }

    @Test
    void kubeSystemPodsExist() {
        List<PodSnapshot> snapshots = scanner.scan();

        // kube-system always has at least the kube-apiserver / coredns pods in minikube
        boolean hasKubeSystemPod = snapshots.stream()
                .anyMatch(p -> "kube-system".equals(p.getNamespace()));

        assertTrue(hasKubeSystemPod,
                "Expected at least one Pod in the kube-system namespace");
    }

    @Test
    void serviceAccountNameIsMappedFromSpec() {
        List<PodSnapshot> snapshots = scanner.scan();

        // At least one pod in kube-system should have a serviceAccountName set
        // (e.g. coredns uses the coredns SA). This validates the spec-level mapping.
        boolean hasServiceAccountName = snapshots.stream()
                .filter(p -> "kube-system".equals(p.getNamespace()))
                .anyMatch(p -> p.getServiceAccountName() != null
                        && !p.getServiceAccountName().isBlank());

        assertTrue(hasServiceAccountName,
                "Expected at least one kube-system Pod to have a non-blank serviceAccountName");
    }

    private static Optional<PodSnapshot> findByNameAndNamespace(
            List<PodSnapshot> snapshots, String name, String namespace) {
        return snapshots.stream()
                .filter(p -> name.equals(p.getName()) && namespace.equals(p.getNamespace()))
                .findFirst();
    }
}
