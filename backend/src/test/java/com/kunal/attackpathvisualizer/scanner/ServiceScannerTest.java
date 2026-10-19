package com.kunal.attackpathvisualizer.scanner;

import com.kunal.attackpathvisualizer.common.model.snapshot.ServiceSnapshot;
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
public class ServiceScannerTest {

    private static KubernetesClient client;
    private static ServiceScanner scanner;

    @BeforeAll
    static void setUp() {
        client = new KubernetesClientBuilder().build();
        scanner = new ServiceScanner(client);
    }

    @AfterAll
    static void tearDown() {
        if (client != null) {
            client.close();
        }
    }

    @Test
    void scanReturnsNonEmptyListFromRealCluster() {
        List<ServiceSnapshot> snapshots = scanner.scan();

        assertNotNull(snapshots, "scan() must never return null");
        // Every cluster has at least the kubernetes ClusterIP service in default
        assertFalse(snapshots.isEmpty(), "Expected at least one Service from the cluster");
    }

    @Test
    void everySnapshotHasRequiredFields() {
        List<ServiceSnapshot> snapshots = scanner.scan();

        for (ServiceSnapshot snapshot : snapshots) {
            assertNotNull(snapshot.getUid(), "uid must be populated from metadata");
            assertNotNull(snapshot.getName(), "name must be populated from metadata");
            assertNotNull(snapshot.getNamespace(), "namespace must be populated — Services are namespace-scoped");
            assertNotNull(snapshot.getLabels(), "labels should fall back to empty map, never null");
            assertNotNull(snapshot.getAnnotations(), "annotations should fall back to empty map, never null");
            assertNotNull(snapshot.getCreationTimestamp(), "creationTimestamp must be parsed");
            assertNotNull(snapshot.getSelector(), "selector must fall back to empty map, never null");
        }
    }

    @Test
    void allSnapshotsAreNamespaceScoped() {
        List<ServiceSnapshot> snapshots = scanner.scan();

        for (ServiceSnapshot snapshot : snapshots) {
            assertNotNull(snapshot.getNamespace(),
                    "Service '" + snapshot.getName() + "' must have a non-null namespace");
        }
    }

    @Test
    void defaultKubernetesServiceExistsInDefaultNamespace() {
        // The 'kubernetes' ClusterIP service is injected into every cluster
        // in the default namespace — a reliable well-known fixture.
        ServiceSnapshot k8sSvc = findByNameAndNamespace(
                scanner.scan(), "kubernetes", "default");

        assertNotNull(k8sSvc,
                "Expected to find 'kubernetes' Service in the default namespace");
        assertEquals("kubernetes", k8sSvc.getName());
        assertEquals("default", k8sSvc.getNamespace());
        assertNotNull(k8sSvc.getUid());
        assertNotNull(k8sSvc.getCreationTimestamp());
    }

    @Test
    void selectorIsNeverNull() {
        List<ServiceSnapshot> snapshots = scanner.scan();

        // ServiceScanner falls back to Collections.emptyMap() when spec.selector is null
        // (e.g. the headless 'kubernetes' service has no selector).
        for (ServiceSnapshot snapshot : snapshots) {
            assertNotNull(snapshot.getSelector(),
                    "selector must never be null for Service '" + snapshot.getName() + "'");
        }
    }

    private static ServiceSnapshot findByNameAndNamespace(
            List<ServiceSnapshot> snapshots, String name, String namespace) {
        Optional<ServiceSnapshot> match = snapshots.stream()
                .filter(s -> name.equals(s.getName()) && namespace.equals(s.getNamespace()))
                .findFirst();
        return match.orElse(null);
    }
}
