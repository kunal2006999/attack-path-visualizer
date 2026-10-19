package com.kunal.attackpathvisualizer.scanner;

import com.kunal.attackpathvisualizer.common.model.snapshot.NamespaceSnapshot;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import org.junit.jupiter.api.Tag;

@Tag("integration")
public class NamespaceScannerTest {

    private static KubernetesClient client;
    private static NamespaceScanner scanner;

    @BeforeAll
    static void setUp() {
        client = new KubernetesClientBuilder().build();
        scanner = new NamespaceScanner(client);
    }

    @AfterAll
    static void tearDown() {
        if (client != null) {
            client.close();
        }
    }

    @Test
    void scanReturnsNonEmptyListFromRealCluster() {
        List<NamespaceSnapshot> snapshots = scanner.scan();

        assertNotNull(snapshots);
        assertFalse(snapshots.isEmpty(), "Expected at least one namespace from the cluster");
    }

    @Test
    void scanMapsDefaultNamespaceCorrectly() {
        NamespaceSnapshot defaultNs = findByName(scanner.scan(), "default");

        assertNotNull(defaultNs, "Expected to find 'default' namespace on the cluster");
        assertEquals("default", defaultNs.getName());
        assertNotNull(defaultNs.getUid(), "uid should be populated from metadata");
        assertNotNull(defaultNs.getCreationTimestamp(), "creationTimestamp should be parsed");
        assertNull(defaultNs.getNamespace(), "Namespaces are cluster-scoped; namespace field must be null");
        assertNotNull(defaultNs.getLabels(), "labels should fall back to empty map, never null");
        assertNotNull(defaultNs.getAnnotations(), "annotations should fall back to empty map, never null");
    }

    @Test
    void scanMapsKubeSystemNamespaceCorrectly() {
        NamespaceSnapshot kubeSystem = findByName(scanner.scan(), "kube-system");

        assertNotNull(kubeSystem, "Expected to find 'kube-system' namespace on the cluster");
        assertEquals("kube-system", kubeSystem.getName());
        assertNotNull(kubeSystem.getUid());
        assertNotNull(kubeSystem.getCreationTimestamp());
        assertNull(kubeSystem.getNamespace());
        assertNotNull(kubeSystem.getLabels());
        assertNotNull(kubeSystem.getAnnotations());
    }

    private static NamespaceSnapshot findByName(List<NamespaceSnapshot> snapshots, String name) {
        Optional<NamespaceSnapshot> match = snapshots.stream()
                .filter(ns -> name.equals(ns.getName()))
                .findFirst();
        return match.orElse(null);
    }
}