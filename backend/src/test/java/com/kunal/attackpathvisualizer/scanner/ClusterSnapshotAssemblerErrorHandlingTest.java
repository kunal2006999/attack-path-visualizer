package com.kunal.attackpathvisualizer.scanner;

import com.kunal.attackpathvisualizer.common.model.snapshot.ClusterSnapshot;
import io.fabric8.kubernetes.api.model.*;
import io.fabric8.kubernetes.api.model.rbac.*;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientException;
import io.fabric8.kubernetes.client.dsl.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link ClusterSnapshotAssembler} error handling.
 *
 * <p>Verifies that:
 * <ul>
 *   <li>A {@link ScannerException} from any individual scanner propagates immediately
 *       through the assembler — no partial snapshot is returned.</li>
 *   <li>A failed scan cannot silently produce a misleading "successful" snapshot.</li>
 *   <li>Constructor guards reject null client / blank cluster name.</li>
 * </ul>
 *
 * <p>Uses {@link Strictness#LENIENT} because the shared {@code @BeforeEach} stub setup
 * is reused across tests that deliberately override specific scanners to trigger failures
 * — making some baseline stubs unreachable in those tests.
 *
 * Does not require Minikube.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ClusterSnapshotAssemblerErrorHandlingTest {

    @Mock private KubernetesClient client;

    // DSL operation mocks — raw types are unavoidable with Fabric8's generic DSL
    @Mock @SuppressWarnings("rawtypes") private NonNamespaceOperation namespacesOp;
    @Mock @SuppressWarnings("rawtypes") private MixedOperation podsOp;
    @Mock @SuppressWarnings("rawtypes") private MixedOperation servicesOp;
    @Mock @SuppressWarnings("rawtypes") private MixedOperation serviceAccountsOp;
    @Mock private RbacAPIGroupDSL rbacApi;
    @Mock @SuppressWarnings("rawtypes") private MixedOperation rolesOp;
    @Mock @SuppressWarnings("rawtypes") private NonNamespaceOperation clusterRolesOp;
    @Mock @SuppressWarnings("rawtypes") private MixedOperation roleBindingsOp;
    @Mock @SuppressWarnings("rawtypes") private NonNamespaceOperation clusterRoleBindingsOp;
    @Mock @SuppressWarnings("rawtypes") private MixedOperation secretsOp;
    @Mock @SuppressWarnings("rawtypes") private MixedOperation configMapsOp;

    // ── Constructor guards ───────────────────────────────────────────────────

    @Test
    void constructorRejectsNullClient() {
        assertThrows(IllegalArgumentException.class,
                () -> new ClusterSnapshotAssembler(null, "test-cluster"));
    }

    @Test
    void constructorRejectsNullClusterName() {
        assertThrows(IllegalArgumentException.class,
                () -> new ClusterSnapshotAssembler(client, null));
    }

    @Test
    void constructorRejectsBlankClusterName() {
        assertThrows(IllegalArgumentException.class,
                () -> new ClusterSnapshotAssembler(client, "   "));
    }

    // ── Happy path (minimal stubs) ───────────────────────────────────────────

    /**
     * Sets up all 10 scanners to return empty lists so that the happy-path scan
     * completes without error and returns a non-null, named snapshot.
     * Lenient strictness allows these baseline stubs to be unused in failure tests.
     */
    @BeforeEach
    @SuppressWarnings("unchecked")
    void stubAllScannersToReturnEmptyLists() {
        // Namespace
        when(client.namespaces()).thenReturn(namespacesOp);
        NamespaceList nsList = new NamespaceList();
        nsList.setItems(List.of());
        when(namespacesOp.list()).thenReturn(nsList);

        // Pods
        when(client.pods()).thenReturn(podsOp);
        when(podsOp.inAnyNamespace()).thenReturn(podsOp);
        PodList podList = new PodList();
        podList.setItems(List.of());
        when(podsOp.list()).thenReturn(podList);

        // Services
        when(client.services()).thenReturn(servicesOp);
        when(servicesOp.inAnyNamespace()).thenReturn(servicesOp);
        ServiceList svcList = new ServiceList();
        svcList.setItems(List.of());
        when(servicesOp.list()).thenReturn(svcList);

        // ServiceAccounts
        when(client.serviceAccounts()).thenReturn(serviceAccountsOp);
        when(serviceAccountsOp.inAnyNamespace()).thenReturn(serviceAccountsOp);
        ServiceAccountList saList = new ServiceAccountList();
        saList.setItems(List.of());
        when(serviceAccountsOp.list()).thenReturn(saList);

        // RBAC DSL
        when(client.rbac()).thenReturn(rbacApi);

        // Roles
        when(rbacApi.roles()).thenReturn(rolesOp);
        when(rolesOp.inAnyNamespace()).thenReturn(rolesOp);
        RoleList roleList = new RoleList();
        roleList.setItems(List.of());
        when(rolesOp.list()).thenReturn(roleList);

        // ClusterRoles
        when(rbacApi.clusterRoles()).thenReturn(clusterRolesOp);
        ClusterRoleList crList = new ClusterRoleList();
        crList.setItems(List.of());
        when(clusterRolesOp.list()).thenReturn(crList);

        // RoleBindings
        when(rbacApi.roleBindings()).thenReturn(roleBindingsOp);
        when(roleBindingsOp.inAnyNamespace()).thenReturn(roleBindingsOp);
        RoleBindingList rbList = new RoleBindingList();
        rbList.setItems(List.of());
        when(roleBindingsOp.list()).thenReturn(rbList);

        // ClusterRoleBindings
        when(rbacApi.clusterRoleBindings()).thenReturn(clusterRoleBindingsOp);
        ClusterRoleBindingList crbList = new ClusterRoleBindingList();
        crbList.setItems(List.of());
        when(clusterRoleBindingsOp.list()).thenReturn(crbList);

        // Secrets
        when(client.secrets()).thenReturn(secretsOp);
        when(secretsOp.inAnyNamespace()).thenReturn(secretsOp);
        SecretList secretList = new SecretList();
        secretList.setItems(List.of());
        when(secretsOp.list()).thenReturn(secretList);

        // ConfigMaps
        when(client.configMaps()).thenReturn(configMapsOp);
        when(configMapsOp.inAnyNamespace()).thenReturn(configMapsOp);
        ConfigMapList cmList = new ConfigMapList();
        cmList.setItems(List.of());
        when(configMapsOp.list()).thenReturn(cmList);
    }

    @Test
    void happyPathReturnsSnapshotWithCorrectClusterName() {
        ClusterSnapshot snapshot =
                new ClusterSnapshotAssembler(client, "test-cluster").scanCluster();

        assertNotNull(snapshot);
        assertEquals("test-cluster", snapshot.getClusterName());
    }

    @Test
    void happyPathSnapshotHasNonNullLists() {
        ClusterSnapshot snapshot =
                new ClusterSnapshotAssembler(client, "test-cluster").scanCluster();

        assertNotNull(snapshot.getNamespaces());
        assertNotNull(snapshot.getPods());
        assertNotNull(snapshot.getServices());
        assertNotNull(snapshot.getServiceAccounts());
        assertNotNull(snapshot.getRoles());
        assertNotNull(snapshot.getClusterRoles());
        assertNotNull(snapshot.getRoleBindings());
        assertNotNull(snapshot.getClusterRoleBindings());
        assertNotNull(snapshot.getSecrets());
        assertNotNull(snapshot.getConfigMaps());
    }

    // ── Scanner failure propagation ──────────────────────────────────────────

    @Test
    @SuppressWarnings("unchecked")
    void namespaceScannerFailurePropagatesAsScannerException() {
        // Override the namespace stub to throw
        when(namespacesOp.list())
                .thenThrow(new KubernetesClientException("namespace API unreachable"));

        ScannerException ex = assertThrows(ScannerException.class,
                () -> new ClusterSnapshotAssembler(client, "test-cluster").scanCluster());

        assertEquals("Namespaces", ex.getResourceCategory());
        assertInstanceOf(KubernetesClientException.class, ex.getCause());
    }

    @Test
    @SuppressWarnings("unchecked")
    void podScannerFailurePropagatesAsScannerException() {
        when(podsOp.list())
                .thenThrow(new KubernetesClientException("pods API unreachable"));

        ScannerException ex = assertThrows(ScannerException.class,
                () -> new ClusterSnapshotAssembler(client, "test-cluster").scanCluster());

        assertEquals("Pods", ex.getResourceCategory());
    }

    @Test
    @SuppressWarnings("unchecked")
    void secretScannerFailurePropagatesAsScannerException() {
        when(secretsOp.list())
                .thenThrow(new KubernetesClientException("secrets API unreachable"));

        ScannerException ex = assertThrows(ScannerException.class,
                () -> new ClusterSnapshotAssembler(client, "test-cluster").scanCluster());

        assertEquals("Secrets", ex.getResourceCategory());
    }

    // ── A failed scan must NOT produce a misleading successful snapshot ──────

    @Test
    @SuppressWarnings("unchecked")
    void failedScanDoesNotReturnPartialSnapshot() {
        // Service scanner fails; scanCluster() must throw, not return an incomplete snapshot
        when(servicesOp.list())
                .thenThrow(new KubernetesClientException("services API unreachable"));

        assertThrows(ScannerException.class,
                () -> new ClusterSnapshotAssembler(client, "test-cluster").scanCluster(),
                "Expected ScannerException to propagate; a partial snapshot was returned instead");
    }

    @Test
    @SuppressWarnings("unchecked")
    void nullApiResponseForNamespacesIsNotTreatedAsEmptySuccess() {
        // Returning null (not an empty list) from the API is anomalous — must throw
        when(namespacesOp.list()).thenReturn(null);

        ScannerException ex = assertThrows(ScannerException.class,
                () -> new ClusterSnapshotAssembler(client, "test-cluster").scanCluster());

        assertEquals("Namespaces", ex.getResourceCategory());
    }
}
