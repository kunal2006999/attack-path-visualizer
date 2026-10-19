package com.kunal.attackpathvisualizer.scanner;

import com.kunal.attackpathvisualizer.common.model.snapshot.ConfigMapSnapshot;
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
public class ConfigMapScannerTest {

    private static KubernetesClient client;
    private static ConfigMapScanner scanner;

    @BeforeAll
    static void setUp() {
        client = new KubernetesClientBuilder().build();
        scanner = new ConfigMapScanner(client);
    }

    @AfterAll
    static void tearDown() {
        if (client != null) {
            client.close();
        }
    }

    @Test
    void scanReturnsNonEmptyListFromRealCluster() {
        List<ConfigMapSnapshot> snapshots = scanner.scan();

        assertNotNull(snapshots, "scan() must never return null");
        assertFalse(snapshots.isEmpty(), "Expected at least one ConfigMap from the cluster");
    }

    @Test
    void everySnapshotHasRequiredFields() {
        List<ConfigMapSnapshot> snapshots = scanner.scan();

        for (ConfigMapSnapshot snapshot : snapshots) {
            assertNotNull(snapshot.getUid(), "uid must be populated from metadata");
            assertNotNull(snapshot.getName(), "name must be populated from metadata");
            assertNotNull(snapshot.getNamespace(), "namespace must be populated — ConfigMaps are namespace-scoped");
            assertNotNull(snapshot.getLabels(), "labels should fall back to empty map, never null");
            assertNotNull(snapshot.getAnnotations(), "annotations should fall back to empty map, never null");
            assertNotNull(snapshot.getCreationTimestamp(), "creationTimestamp must be parsed");
        }
    }

    @Test
    void allSnapshotsAreNamespaceScoped() {
        List<ConfigMapSnapshot> snapshots = scanner.scan();

        for (ConfigMapSnapshot snapshot : snapshots) {
            assertNotNull(snapshot.getNamespace(),
                    "ConfigMap '" + snapshot.getName() + "' must have a non-null namespace");
        }
    }

    @Test
    void kubeSystemNamespaceContainsKubeRootCaConfigMap() {
        // kube-root-ca.crt is a ConfigMap injected into every namespace by the
        // Kubernetes control plane; verifying it exists in kube-system is a
        // reliable way to assert the scanner retrieves real cluster data.
        ConfigMapSnapshot kubeRootCa = findByNameAndNamespace(
                scanner.scan(), "kube-root-ca.crt", "kube-system");

        assertNotNull(kubeRootCa,
                "Expected to find 'kube-root-ca.crt' ConfigMap in kube-system namespace");
        assertEquals("kube-root-ca.crt", kubeRootCa.getName());
        assertEquals("kube-system", kubeRootCa.getNamespace());
        assertNotNull(kubeRootCa.getUid());
        assertNotNull(kubeRootCa.getCreationTimestamp());
    }

    private static ConfigMapSnapshot findByNameAndNamespace(
            List<ConfigMapSnapshot> snapshots, String name, String namespace) {
        Optional<ConfigMapSnapshot> match = snapshots.stream()
                .filter(cm -> name.equals(cm.getName()) && namespace.equals(cm.getNamespace()))
                .findFirst();
        return match.orElse(null);
    }
}
