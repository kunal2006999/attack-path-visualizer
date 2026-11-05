package com.kunal.attackpathvisualizer.integration;

import com.kunal.attackpathvisualizer.common.util.ClusterSnapshotParser;
import com.kunal.attackpathvisualizer.core.builder.ClusterSnapshotMapper;
import com.kunal.attackpathvisualizer.core.enums.ResourceType;
import com.kunal.attackpathvisualizer.core.pipeline.ClusterGraphPipeline;
import com.kunal.attackpathvisualizer.core.validation.ClusterSnapshotValidator;
import com.kunal.attackpathvisualizer.graph.AttackGraph;
import com.kunal.attackpathvisualizer.graph.GraphBuilder;
import com.kunal.attackpathvisualizer.graph.GraphEdge;
import com.kunal.attackpathvisualizer.graph.GraphNode;
import com.kunal.attackpathvisualizer.report.SecurityReportExporter;
import com.kunal.attackpathvisualizer.security.AttackPathAnalyzer;
import com.kunal.attackpathvisualizer.security.CriticalResource;
import com.kunal.attackpathvisualizer.security.CriticalResourceAnalyzer;
import com.kunal.attackpathvisualizer.security.Finding;
import com.kunal.attackpathvisualizer.security.RecommendationEngine;
import com.kunal.attackpathvisualizer.security.RiskScorer;
import com.kunal.attackpathvisualizer.security.ScoreFactor;
import com.kunal.attackpathvisualizer.security.SecretSensitivityClassifier;
import com.kunal.attackpathvisualizer.security.SecurityAnalysisService;
import com.kunal.attackpathvisualizer.security.SecurityReport;
import com.kunal.attackpathvisualizer.security.Severity;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Live cluster -> scanners -> assembler -> pipeline -> graph -> security report.
 *
 * Only findings whose entry point is in the test namespace are asserted on:
 * Minikube's own system workloads may produce other findings, including ones
 * that target the test Secret.
 */
@Tag("integration")
class LiveSecurityPipelineIntegrationTest {

    private static final String NS = "attackpath-test-pipeline";
    private static final String CLUSTER_NAME = "minikube-it";

    private static LiveClusterFixture fx;
    private static ClusterGraphPipeline.PipelineResult result;
    private static SecurityReport report;

    private static String podId;
    private static String saId;
    private static String rbId;
    private static String roleId;
    private static String secretId;
    private static String serviceId;
    private static String configMapId;
    private static String crbId;
    private static String crId;

    @BeforeAll
    static void setUp() {
        fx = new LiveClusterFixture(NS);
        fx.setUp();

        podId = fx.id("POD", LiveClusterFixture.POD);
        saId = fx.id("SERVICE_ACCOUNT", LiveClusterFixture.SA);
        rbId = fx.id("ROLE_BINDING", LiveClusterFixture.ROLE_BINDING);
        roleId = fx.id("ROLE", LiveClusterFixture.ROLE);
        secretId = fx.id("SECRET", LiveClusterFixture.SECRET);
        serviceId = fx.id("SERVICE", LiveClusterFixture.SERVICE);
        configMapId = fx.id("CONFIG_MAP", LiveClusterFixture.CONFIG_MAP);
        crbId = LiveClusterFixture.clusterId("CLUSTER_ROLE_BINDING", fx.clusterRoleBindingName);
        crId = LiveClusterFixture.clusterId("CLUSTER_ROLE", fx.clusterRoleName);

        ClusterGraphPipeline pipeline = new ClusterGraphPipeline(
                new ClusterSnapshotParser(),
                new ClusterSnapshotValidator(),
                new ClusterSnapshotMapper(),
                new GraphBuilder());

        result = pipeline.buildFromLiveCluster(fx.client, CLUSTER_NAME);

        report = new SecurityAnalysisService(
                new AttackPathAnalyzer(new SecretSensitivityClassifier(), new RiskScorer()),
                new CriticalResourceAnalyzer(),
                new RecommendationEngine()).analyze(result);
    }

    @AfterAll
    static void tearDown() {
        if (fx != null) {
            fx.close();
        }
    }

    // ------------------------------------------------------------------
    // graph nodes
    // ------------------------------------------------------------------

    @Test
    void graphContainsLiveResourcesWithCorrectTypesAndUids() {
        AttackGraph g = result.graph();
        assertEquals(CLUSTER_NAME, result.snapshot().getClusterName());

        assertNode(g, podId, ResourceType.POD, fx.podObj.getMetadata().getUid());
        assertNode(g, saId, ResourceType.SERVICE_ACCOUNT, fx.serviceAccountObj.getMetadata().getUid());
        assertNode(g, rbId, ResourceType.ROLE_BINDING, fx.roleBindingObj.getMetadata().getUid());
        assertNode(g, roleId, ResourceType.ROLE, fx.roleObj.getMetadata().getUid());
        assertNode(g, secretId, ResourceType.SECRET, fx.secretObj.getMetadata().getUid());
        assertNode(g, serviceId, ResourceType.SERVICE, fx.serviceObj.getMetadata().getUid());
        assertNode(g, configMapId, ResourceType.CONFIG_MAP, fx.configMapObj.getMetadata().getUid());
        assertNode(g, crbId, ResourceType.CLUSTER_ROLE_BINDING, fx.clusterRoleBindingObj.getMetadata().getUid());
        assertNode(g, crId, ResourceType.CLUSTER_ROLE, fx.clusterRoleObj.getMetadata().getUid());
        assertNode(g, "NAMESPACE:" + NS, ResourceType.NAMESPACE, fx.namespaceObj.getMetadata().getUid());

        // Cluster-scoped resources carry no namespace; namespaced ones do.
        assertNull(g.getNode(crbId).getNamespace());
        assertNull(g.getNode(crId).getNamespace());
        assertEquals(NS, g.getNode(podId).getNamespace());
    }

    // ------------------------------------------------------------------
    // graph edges
    // ------------------------------------------------------------------

    @Test
    void graphContainsExpectedRelationshipsWithCorrectDirection() {
        AttackGraph g = result.graph();

        assertEquals(Set.of("USES->" + saId), outgoing(g, podId));
        assertEquals(Set.of("HAS_BINDING->" + rbId, "HAS_BINDING->" + crbId), outgoing(g, saId));
        assertEquals(Set.of("GRANTS->" + roleId), outgoing(g, rbId));
        assertEquals(Set.of("CAN_ACCESS->" + secretId), outgoing(g, roleId));
        assertEquals(Set.of("GRANTS->" + crId), outgoing(g, crbId));
        assertEquals(Set.of("SELECTS->" + podId), outgoing(g, serviceId));

        // The shared ClusterRole node carries no grants; no Secret access via the CRB either.
        assertTrue(outgoing(g, crId).isEmpty());
        assertTrue(outgoing(g, configMapId).isEmpty());
        assertTrue(outgoing(g, secretId).isEmpty());
    }

    // ------------------------------------------------------------------
    // finding
    // ------------------------------------------------------------------

    @Test
    void liveClusterProducesExpectedFindingForTestPod() {
        List<Finding> mine = report.findings().stream()
                .filter(f -> NS.equals(f.entryPoint().getNamespace()))
                .toList();

        assertEquals(1, mine.size(), "Expected exactly one finding for the test Pod");
        Finding f = mine.get(0);

        assertEquals(podId, f.entryPoint().getId());
        assertEquals(secretId, f.target().getId());
        assertEquals(List.of(podId, saId, rbId, roleId, secretId),
                f.attackPath().stream().map(GraphNode::getId).toList());

        // Hand-derived: Opaque 20 + sensitive label 5 + "credential" in name 5 = 30;
        // Role grant source = 10; no wildcards = 0; 4 edges = 3.
        Map<String, Integer> factors = new LinkedHashMap<>();
        for (ScoreFactor sf : f.scoreFactors()) {
            factors.put(sf.name(), sf.points());
        }
        Map<String, Integer> expected = new LinkedHashMap<>();
        expected.put("SECRET_SENSITIVITY", 30);
        expected.put("PERMISSION_SCOPE", 10);
        expected.put("WILDCARD_PERMISSION", 0);
        expected.put("ATTACK_PATH_LENGTH", 3);
        assertEquals(expected, factors);

        assertEquals(43, f.riskScore());
        assertEquals(Severity.MEDIUM, f.severity());
        assertTrue(f.recommendation().contains("Role's rules"));
        assertTrue(f.description().contains("'" + LiveClusterFixture.POD + "'"));
        assertTrue(f.description().contains("'" + LiveClusterFixture.SECRET + "'"));
    }

    @Test
    void entireLiveReportIsInternallyConsistent() {
        int total = 0;
        for (Severity s : Severity.values()) {
            int expected = (int) report.findings().stream().filter(f -> f.severity() == s).count();
            int actual = report.severityCounts().get(s);
            assertEquals(expected, actual, "count for " + s);
            total += actual;
        }
        assertEquals(report.totalFindings(), total);
        assertEquals(report.findings().size(), report.totalFindings());

        for (Finding f : report.findings()) {
            assertTrue(f.riskScore() >= 0 && f.riskScore() <= 100);
            assertEquals(Severity.of(f.riskScore()), f.severity());
            assertEquals(f.entryPoint().getId(), f.attackPath().get(0).getId());
            assertEquals(f.target().getId(), f.attackPath().get(f.attackPath().size() - 1).getId());
            assertFalse(f.recommendation().isBlank());
        }
        assertNotNull(report.generatedAt());
    }

    // ------------------------------------------------------------------
    // critical resources
    // ------------------------------------------------------------------

    @Test
    void criticalResourcesForTestScenarioAreCorrect() {
        Map<String, CriticalResource> byId = new HashMap<>();
        for (CriticalResource cr : report.criticalResources()) {
            byId.put(cr.resource().getId(), cr);
        }

        // score = min(findings*15,45) + min(secrets*10,40) + (ClusterRoleBinding ? 15 : 0)
        assertCritical(byId.get(podId), 25, 1, 1);
        assertCritical(byId.get(saId), 25, 1, 1);
        assertCritical(byId.get(rbId), 25, 1, 1);
        assertCritical(byId.get(roleId), 25, 1, 1);
        assertCritical(byId.get(serviceId), 10, 1, 0);
        assertCritical(byId.get(crbId), 15, 0, 0); // included because it is a ClusterRoleBinding

        // Other findings (e.g. from system workloads) may also target this Secret.
        CriticalResource secret = byId.get(secretId);
        assertNotNull(secret);
        assertTrue(secret.findingCount() >= 1);
        assertEquals(0, secret.affectedSecretCount());

        // Nothing reaches a Secret from these, and they are in no finding.
        assertNull(byId.get(crId));
        assertNull(byId.get(configMapId));
    }

    // ------------------------------------------------------------------
    // exported JSON
    // ------------------------------------------------------------------

    @Test
    void exportedJsonContainsTheLiveFinding() {
        String json = new SecurityReportExporter().export(CLUSTER_NAME, report);
        JsonNode root = new ObjectMapper().readTree(json);

        assertEquals(CLUSTER_NAME, root.get("clusterName").textValue());
        assertEquals(report.totalFindings(), root.get("totalFindings").intValue());
        assertEquals(4, root.get("severityCounts").size());

        JsonNode ours = null;
        for (JsonNode f : root.get("findings")) {
            if (podId.equals(f.get("entryPoint").get("id").textValue())) {
                ours = f;
            }
        }
        assertNotNull(ours, "Exported report must contain the test Pod finding");
        assertEquals(43, ours.get("riskScore").intValue());
        assertEquals("MEDIUM", ours.get("severity").textValue());
        assertEquals(secretId, ours.get("target").get("id").textValue());
        assertEquals(5, ours.get("attackPath").size());
        assertEquals(4, ours.get("scoreFactors").size());
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    private static void assertNode(AttackGraph g, String id, ResourceType type, String uid) {
        GraphNode n = g.getNode(id);
        assertNotNull(n, "Missing graph node " + id);
        assertEquals(type, n.getResourceType(), "type of " + id);
        assertEquals(uid, n.getResourceId(), "uid of " + id);
    }

    private static Set<String> outgoing(AttackGraph g, String id) {
        List<GraphEdge> edges = g.getOutgoingEdges(id);
        Set<String> out = new HashSet<>();
        for (GraphEdge e : edges) {
            out.add(e.getRelationshipType() + "->" + e.getTarget().getId());
        }
        assertEquals(edges.size(), out.size(), "Duplicate edges from " + id);
        return out;
    }

    private static void assertCritical(CriticalResource cr, int score, int secrets, int findings) {
        assertNotNull(cr, "Expected a critical resource entry");
        String id = cr.resource().getId();
        assertEquals(score, cr.riskScore(), "riskScore of " + id);
        assertEquals(secrets, cr.affectedSecretCount(), "affectedSecretCount of " + id);
        assertEquals(findings, cr.findingCount(), "findingCount of " + id);
    }
}