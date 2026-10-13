package com.kunal.attackpathvisualizer.scanner;

import com.kunal.attackpathvisualizer.common.model.snapshot.ServiceAccountSnapshot;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

public class ServiceAccountScannerTest {

    private static KubernetesClient client;
    private static ServiceAccountScanner scanner;

    @BeforeAll
    static void setUp() {
        client = new KubernetesClientBuilder().build();
        scanner = new ServiceAccountScanner(client);
    }

    @AfterAll
    static void tearDown() {
        if (client != null) {
            client.close();
        }
    }

    @Test
    void scanReturnsNonEmptyListFromRealCluster() {
        List<ServiceAccountSnapshot> snapshots = scanner.scan();

        assertNotNull(snapshots, "scan() must never return null");
        // Every namespace gets a 'default' ServiceAccount automatically
        assertFalse(snapshots.isEmpty(), "Expected at least one ServiceAccount from the cluster");
    }

    @Test
    void everySnapshotHasRequiredFields() {
        List<ServiceAccountSnapshot> snapshots = scanner.scan();

        for (ServiceAccountSnapshot snapshot : snapshots) {
            assertNotNull(snapshot.getUid(), "uid must be populated from metadata");
            assertNotNull(snapshot.getName(), "name must be populated from metadata");
            assertNotNull(snapshot.getNamespace(), "namespace must be populated — ServiceAccounts are namespace-scoped");
            assertNotNull(snapshot.getLabels(), "labels should fall back to empty map, never null");
            assertNotNull(snapshot.getAnnotations(), "annotations should fall back to empty map, never null");
            assertNotNull(snapshot.getCreationTimestamp(), "creationTimestamp must be parsed");
        }
    }

    @Test
    void allSnapshotsAreNamespaceScoped() {
        List<ServiceAccountSnapshot> snapshots = scanner.scan();

        for (ServiceAccountSnapshot snapshot : snapshots) {
            assertNotNull(snapshot.getNamespace(),
                    "ServiceAccount '" + snapshot.getName() + "' must have a non-null namespace");
        }
    }

    @Test
    void defaultServiceAccountExistsInDefaultNamespace() {
        // The 'default' ServiceAccount is auto-created in every namespace —
        // checking it in 'default' is a reliable well-known fixture.
        ServiceAccountSnapshot defaultSa = findByNameAndNamespace(
                scanner.scan(), "default", "default");

        assertNotNull(defaultSa,
                "Expected to find 'default' ServiceAccount in the default namespace");
        assertEquals("default", defaultSa.getName());
        assertEquals("default", defaultSa.getNamespace());
        assertNotNull(defaultSa.getUid());
        assertNotNull(defaultSa.getCreationTimestamp());
        assertNotNull(defaultSa.getLabels());
        assertNotNull(defaultSa.getAnnotations());
    }

    @Test
    void defaultServiceAccountExistsInKubeSystem() {
        ServiceAccountSnapshot kubeSystemDefault = findByNameAndNamespace(
                scanner.scan(), "default", "kube-system");

        assertNotNull(kubeSystemDefault,
                "Expected to find 'default' ServiceAccount in kube-system namespace");
        assertEquals("kube-system", kubeSystemDefault.getNamespace());
    }

    private static ServiceAccountSnapshot findByNameAndNamespace(
            List<ServiceAccountSnapshot> snapshots, String name, String namespace) {
        Optional<ServiceAccountSnapshot> match = snapshots.stream()
                .filter(sa -> name.equals(sa.getName()) && namespace.equals(sa.getNamespace()))
                .findFirst();
        return match.orElse(null);
    }
}
