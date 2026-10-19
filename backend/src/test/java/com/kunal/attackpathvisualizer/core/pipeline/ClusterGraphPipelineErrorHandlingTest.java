package com.kunal.attackpathvisualizer.core.pipeline;

import com.kunal.attackpathvisualizer.common.model.snapshot.ClusterSnapshot;
import com.kunal.attackpathvisualizer.common.util.ClusterSnapshotParser;
import com.kunal.attackpathvisualizer.core.builder.ClusterSnapshotMapper;
import com.kunal.attackpathvisualizer.core.validation.ClusterSnapshotValidator;
import com.kunal.attackpathvisualizer.graph.GraphBuilder;
import com.kunal.attackpathvisualizer.scanner.ScannerException;
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
 * Unit tests for {@link ClusterGraphPipeline} error handling.
 *
 * <p>Verifies:
 * <ul>
 *   <li>A {@link ScannerException} from a live-cluster scan propagates through
 *       {@code buildFromLiveCluster} without being swallowed.</li>
 *   <li>An invalid snapshot causes {@code build} to throw {@link IllegalArgumentException}.</li>
 *   <li>A pipeline failure never silently produces a misleading empty graph.</li>
 * </ul>
 *
 * <p>Uses {@link Strictness#LENIENT} because the shared {@code @BeforeEach} stub setup
 * is reused across tests that deliberately inject failures early in the scanner chain.
 *
 * Does not require Minikube.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ClusterGraphPipelineErrorHandlingTest {

    private ClusterGraphPipeline pipeline;

    @Mock private KubernetesClient client;
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

    @BeforeEach
    void setUp() {
        pipeline = new ClusterGraphPipeline(
                new ClusterSnapshotParser(),
                new ClusterSnapshotValidator(),
                new ClusterSnapshotMapper(),
                new GraphBuilder());
    }

    /**
     * Stubs all 10 scanners to return empty lists so the pipeline succeeds by default.
     * Individual tests override specific scanners to inject failures.
     * Lenient strictness is set at the class level to allow unused stubs in failure tests.
     */
    @BeforeEach
    @SuppressWarnings("unchecked")
    void stubAllScannersToReturnEmptyLists() {
        when(client.namespaces()).thenReturn(namespacesOp);
        NamespaceList nsList = new NamespaceList();
        nsList.setItems(List.of());
        when(namespacesOp.list()).thenReturn(nsList);

        when(client.pods()).thenReturn(podsOp);
        when(podsOp.inAnyNamespace()).thenReturn(podsOp);
        PodList podList = new PodList();
        podList.setItems(List.of());
        when(podsOp.list()).thenReturn(podList);

        when(client.services()).thenReturn(servicesOp);
        when(servicesOp.inAnyNamespace()).thenReturn(servicesOp);
        ServiceList svcList = new ServiceList();
        svcList.setItems(List.of());
        when(servicesOp.list()).thenReturn(svcList);

        when(client.serviceAccounts()).thenReturn(serviceAccountsOp);
        when(serviceAccountsOp.inAnyNamespace()).thenReturn(serviceAccountsOp);
        ServiceAccountList saList = new ServiceAccountList();
        saList.setItems(List.of());
        when(serviceAccountsOp.list()).thenReturn(saList);

        when(client.rbac()).thenReturn(rbacApi);

        when(rbacApi.roles()).thenReturn(rolesOp);
        when(rolesOp.inAnyNamespace()).thenReturn(rolesOp);
        RoleList roleList = new RoleList();
        roleList.setItems(List.of());
        when(rolesOp.list()).thenReturn(roleList);

        when(rbacApi.clusterRoles()).thenReturn(clusterRolesOp);
        ClusterRoleList crList = new ClusterRoleList();
        crList.setItems(List.of());
        when(clusterRolesOp.list()).thenReturn(crList);

        when(rbacApi.roleBindings()).thenReturn(roleBindingsOp);
        when(roleBindingsOp.inAnyNamespace()).thenReturn(roleBindingsOp);
        RoleBindingList rbList = new RoleBindingList();
        rbList.setItems(List.of());
        when(roleBindingsOp.list()).thenReturn(rbList);

        when(rbacApi.clusterRoleBindings()).thenReturn(clusterRoleBindingsOp);
        ClusterRoleBindingList crbList = new ClusterRoleBindingList();
        crbList.setItems(List.of());
        when(clusterRoleBindingsOp.list()).thenReturn(crbList);

        when(client.secrets()).thenReturn(secretsOp);
        when(secretsOp.inAnyNamespace()).thenReturn(secretsOp);
        SecretList secretList = new SecretList();
        secretList.setItems(List.of());
        when(secretsOp.list()).thenReturn(secretList);

        when(client.configMaps()).thenReturn(configMapsOp);
        when(configMapsOp.inAnyNamespace()).thenReturn(configMapsOp);
        ConfigMapList cmList = new ConfigMapList();
        cmList.setItems(List.of());
        when(configMapsOp.list()).thenReturn(cmList);
    }

    // ── Happy path ───────────────────────────────────────────────────────────

    @Test
    void buildFromLiveClusterSucceedsWithAllEmptyScanners() {
        ClusterGraphPipeline.PipelineResult result =
                pipeline.buildFromLiveCluster(client, "test-cluster");

        assertNotNull(result);
        assertNotNull(result.graph());
        assertEquals(0, result.graph().getNodeCount());
    }

    // ── Scanner failure propagation ──────────────────────────────────────────

    @Test
    @SuppressWarnings("unchecked")
    void scannerExceptionPropagatesThroughBuildFromLiveCluster() {
        when(namespacesOp.list())
                .thenThrow(new KubernetesClientException("simulated API failure"));

        ScannerException ex = assertThrows(ScannerException.class,
                () -> pipeline.buildFromLiveCluster(client, "test-cluster"));

        assertEquals("Namespaces", ex.getResourceCategory());
        assertInstanceOf(KubernetesClientException.class, ex.getCause());
    }

    @Test
    @SuppressWarnings("unchecked")
    void podScannerExceptionPropagatesThroughPipeline() {
        when(podsOp.list())
                .thenThrow(new KubernetesClientException("pods forbidden"));

        ScannerException ex = assertThrows(ScannerException.class,
                () -> pipeline.buildFromLiveCluster(client, "test-cluster"));

        assertEquals("Pods", ex.getResourceCategory());
    }

    // ── Invalid snapshot rejected by build() ────────────────────────────────

    @Test
    void buildRejectsNullSnapshot() {
        assertThrows(IllegalArgumentException.class, () -> pipeline.build(null));
    }

    @Test
    void buildRejectsSnapshotWithNoClusterName() {
        ClusterSnapshot snapshot = new ClusterSnapshot();
        // clusterName is intentionally not set
        assertThrows(IllegalArgumentException.class, () -> pipeline.build(snapshot));
    }

    // ── Failed scan must NOT produce an empty successful graph ───────────────

    @Test
    @SuppressWarnings("unchecked")
    void failedScanDoesNotProduceSilentEmptyGraph() {
        // Secrets scanner fails — the pipeline must throw, not return an empty graph
        when(secretsOp.list())
                .thenThrow(new KubernetesClientException("secrets forbidden"));

        assertThrows(ScannerException.class,
                () -> pipeline.buildFromLiveCluster(client, "test-cluster"),
                "Expected ScannerException; pipeline silently returned an empty graph instead");
    }
}
