package com.kunal.attackpathvisualizer.e2e;

import com.kunal.attackpathvisualizer.common.exception.GlobalExceptionHandler;
import com.kunal.attackpathvisualizer.common.model.snapshot.ClusterSnapshot;
import com.kunal.attackpathvisualizer.common.util.ClusterSnapshotParser;
import com.kunal.attackpathvisualizer.core.builder.ClusterSnapshotMapper;
import com.kunal.attackpathvisualizer.core.pipeline.ClusterGraphPipeline;
import com.kunal.attackpathvisualizer.core.validation.ClusterSnapshotValidator;
import com.kunal.attackpathvisualizer.graph.AttackGraph;
import com.kunal.attackpathvisualizer.graph.GraphBuilder;
import com.kunal.attackpathvisualizer.graph.GraphEdge;
import com.kunal.attackpathvisualizer.graph.GraphNode;
import com.kunal.attackpathvisualizer.report.SecurityReportController;
import com.kunal.attackpathvisualizer.report.SecurityReportExportService;
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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * End-to-end validation: vulnerable-cluster.json -> parse -> validate -> map ->
 * graph -> security analysis -> report -> JSON, plus the REST endpoint.
 *
 * Expected values are derived by hand from the fixture and the documented
 * scoring rules, NOT computed by production code.
 */
class EndToEndSecurityAnalysisTest {

    private static final Path FIXTURE =
            Path.of("sample-data", "clusters", "vulnerable-cluster.json");
    private static final String URL = "/api/security/reports/export";

    // ---- expected node ids ----
    private static final String POD = "POD:production:backend-pod";
    private static final String SA = "SERVICE_ACCOUNT:production:backend-sa";
    private static final String RB = "ROLE_BINDING:production:backend-secret-reader";
    private static final String ROLE = "ROLE:production:secret-reader";
    private static final String CRB = "CLUSTER_ROLE_BINDING:backend-cluster-admin";
    private static final String CR = "CLUSTER_ROLE:cluster-admin";
    private static final String SECRET = "SECRET:production:database-secret";
    private static final String NS = "NAMESPACE:production";

    private static final List<String> CRITICAL_PATH = List.of(POD, SA, CRB, SECRET);
    private static final List<String> MEDIUM_PATH = List.of(POD, SA, RB, ROLE, SECRET);

    private final ObjectMapper mapper = new ObjectMapper();
    private final ClusterSnapshotParser parser = new ClusterSnapshotParser();

    private ClusterGraphPipeline pipeline;
    private SecurityAnalysisService analysisService;
    private SecurityReportExporter exporter;
    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        pipeline = new ClusterGraphPipeline(
                parser,
                new ClusterSnapshotValidator(),
                new ClusterSnapshotMapper(),
                new GraphBuilder());
        analysisService = new SecurityAnalysisService(
                new AttackPathAnalyzer(new SecretSensitivityClassifier(), new RiskScorer()),
                new CriticalResourceAnalyzer(),
                new RecommendationEngine());
        exporter = new SecurityReportExporter();

        SecurityReportExportService exportService =
                new SecurityReportExportService(pipeline, analysisService, exporter);
        mockMvc = MockMvcBuilders
                .standaloneSetup(new SecurityReportController(exportService))
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    // ------------------------------------------------------------------
    // 1. Resource discovery (snapshot level)
    // ------------------------------------------------------------------

    @Test
    void snapshotContainsExpectedResources() throws Exception {
        ClusterSnapshot s = parser.parse(FIXTURE);

        assertEquals("vulnerable-cluster", s.getClusterName());
        assertEquals(1, s.getNamespaces().size());
        assertEquals(1, s.getPods().size());
        assertEquals(1, s.getServiceAccounts().size());
        assertEquals(1, s.getRoles().size());
        assertEquals(1, s.getClusterRoles().size());
        assertEquals(1, s.getRoleBindings().size());
        assertEquals(1, s.getClusterRoleBindings().size());
        assertEquals(1, s.getSecrets().size());
        // The fixture has no Services or ConfigMaps; nothing to assert beyond emptiness.
        assertTrue(s.getServices().isEmpty());
        assertTrue(s.getConfigMaps().isEmpty());

        assertEquals("backend-pod", s.getPods().get(0).getName());
        assertEquals("backend-sa", s.getPods().get(0).getServiceAccountName());
        assertEquals("Opaque", s.getSecrets().get(0).getSecretType());
        assertEquals("cluster-admin", s.getClusterRoleBindings().get(0).getClusterRoleName());
    }

    // ------------------------------------------------------------------
    // 2. Graph construction
    // ------------------------------------------------------------------

    @Test
    void graphContainsExactlyExpectedNodesAndEdges() throws Exception {
        AttackGraph graph = pipeline.buildFromJson(FIXTURE).graph();

        Map<String, String> expectedNodes = new HashMap<>();
        expectedNodes.put(NS, "NAMESPACE");
        expectedNodes.put(POD, "POD");
        expectedNodes.put(SA, "SERVICE_ACCOUNT");
        expectedNodes.put(RB, "ROLE_BINDING");
        expectedNodes.put(ROLE, "ROLE");
        expectedNodes.put(CRB, "CLUSTER_ROLE_BINDING");
        expectedNodes.put(CR, "CLUSTER_ROLE");
        expectedNodes.put(SECRET, "SECRET");

        assertEquals(expectedNodes.size(), graph.getNodeCount());
        expectedNodes.forEach((id, type) -> {
            GraphNode n = graph.getNode(id);
            assertNotNull(n, "Missing node " + id);
            assertEquals(type, n.getResourceType().name(), "Wrong type for " + id);
        });

        // Cluster-scoped resources carry no namespace.
        assertNull(graph.getNode(CRB).getNamespace());
        assertNull(graph.getNode(CR).getNamespace());
        assertEquals("production", graph.getNode(POD).getNamespace());

        List<String> actualEdges = new ArrayList<>();
        for (GraphNode node : graph.getNodes()) {
            for (GraphEdge e : graph.getOutgoingEdges(node.getId())) {
                actualEdges.add(e.getSource().getId() + " -" + e.getRelationshipType()
                        + "-> " + e.getTarget().getId());
                assertEquals(1, e.getWeight());
            }
        }

        Set<String> expectedEdges = Set.of(
                POD + " -USES-> " + SA,
                SA + " -HAS_BINDING-> " + RB,
                SA + " -HAS_BINDING-> " + CRB,
                RB + " -GRANTS-> " + ROLE,
                ROLE + " -CAN_ACCESS-> " + SECRET,
                CRB + " -GRANTS-> " + CR,
                CRB + " -CAN_ACCESS-> " + SECRET);

        assertEquals(7, actualEdges.size(), "Unexpected edge count (duplicates?)");
        assertEquals(7, graph.getEdgeCount());
        assertEquals(expectedEdges, new HashSet<>(actualEdges));
    }

    // ------------------------------------------------------------------
    // 3. Findings, scoring, recommendations, critical resources
    // ------------------------------------------------------------------

    @Test
    void securityReportContainsExpectedFindings() throws Exception {
        SecurityReport report = analysisService.analyze(pipeline.buildFromJson(FIXTURE));

        assertEquals(2, report.totalFindings());
        assertEquals(2, report.findings().size());
        assertEquals(0, report.severityCounts().get(Severity.LOW));
        assertEquals(1, report.severityCounts().get(Severity.MEDIUM));
        assertEquals(0, report.severityCounts().get(Severity.HIGH));
        assertEquals(1, report.severityCounts().get(Severity.CRITICAL));
        assertNotNull(report.generatedAt());

        Finding critical = findBySeverity(report, Severity.CRITICAL);
        Finding medium = findBySeverity(report, Severity.MEDIUM);

        assertNotEquals(critical.id(), medium.id());

        // --- CRITICAL: via ClusterRoleBinding ---
        assertEquals(POD, critical.entryPoint().getId());
        assertEquals(SECRET, critical.target().getId());
        assertEquals(CRITICAL_PATH, nodeIds(critical.attackPath()));
        assertEquals(90, critical.riskScore());
        assertEquals(
                factors(30, 30, 25, 5),
                factorPoints(critical.scoreFactors()));
        assertTrue(critical.recommendation().contains("ClusterRoleBinding's subjects"));

        // --- MEDIUM: via RoleBinding -> Role ---
        assertEquals(POD, medium.entryPoint().getId());
        assertEquals(SECRET, medium.target().getId());
        assertEquals(MEDIUM_PATH, nodeIds(medium.attackPath()));
        assertEquals(43, medium.riskScore());
        assertEquals(
                factors(30, 10, 0, 3),
                factorPoints(medium.scoreFactors()));
        assertTrue(medium.recommendation().contains("Role's rules"));
        assertFalse(medium.recommendation().contains("ClusterRoleBinding"));

        // Score == sum of factors (below the cap) and severity consistent.
        for (Finding f : report.findings()) {
            int sum = f.scoreFactors().stream().mapToInt(ScoreFactor::points).sum();
            assertEquals(Math.min(sum, 100), f.riskScore());
            assertEquals(Severity.of(f.riskScore()), f.severity());
        }

        // --- Critical resources (hand-derived) ---
        Map<String, int[]> expected = new LinkedHashMap<>();
        // id -> {riskScore, affectedSecretCount, findingCount}
        expected.put(CRB, new int[]{40, 1, 1});
        expected.put(POD, new int[]{40, 1, 2});
        expected.put(SA, new int[]{40, 1, 2});
        expected.put(SECRET, new int[]{30, 0, 2});
        expected.put(ROLE, new int[]{25, 1, 1});
        expected.put(RB, new int[]{25, 1, 1});

        assertEquals(expected.size(), report.criticalResources().size());
        // Ordering: score desc, then id asc.
        assertEquals(new ArrayList<>(expected.keySet()),
                report.criticalResources().stream()
                        .map(cr -> cr.resource().getId()).toList());
        for (CriticalResource cr : report.criticalResources()) {
            int[] e = expected.get(cr.resource().getId());
            assertNotNull(e, "Unexpected critical resource " + cr.resource().getId());
            assertEquals(e[0], cr.riskScore(), cr.resource().getId());
            assertEquals(e[1], cr.affectedSecretCount(), cr.resource().getId());
            assertEquals(e[2], cr.findingCount(), cr.resource().getId());
        }
        // Resources that appear in no finding and reach no Secret are excluded.
        assertTrue(report.criticalResources().stream()
                .noneMatch(cr -> cr.resource().getId().equals(CR)
                        || cr.resource().getId().equals(NS)));
    }

    // ------------------------------------------------------------------
    // 4. Exported JSON
    // ------------------------------------------------------------------

    @Test
    void exportedJsonMatchesExpectedReport() throws Exception {
        SecurityReport report = analysisService.analyze(pipeline.buildFromJson(FIXTURE));
        String json = exporter.export("vulnerable-cluster", report);

        JsonNode root = mapper.readTree(json);
        assertExpectedVulnerableReport(root);

        // JSON must agree with the in-memory report.
        assertEquals(report.totalFindings(), root.get("totalFindings").intValue());
        assertEquals(report.generatedAt().toString(), root.get("generatedAt").textValue());
        for (Severity s : Severity.values()) {
            assertEquals(report.severityCounts().get(s),
                    root.get("severityCounts").get(s.name()).intValue());
        }
    }

    // ------------------------------------------------------------------
    // 5. REST API
    // ------------------------------------------------------------------

    @Test
    void restEndpointReturnsSameReport() throws Exception {
        MockHttpServletResponse response = postFixture(URL);

        assertEquals(200, response.getStatus());
        assertTrue(response.getContentType().startsWith("application/json"));
        assertNull(response.getHeader("Content-Disposition"));

        assertExpectedVulnerableReport(mapper.readTree(response.getContentAsString()));
    }

    @Test
    void restDownloadHasAttachmentHeaderAndValidBody() throws Exception {
        MockHttpServletResponse response = postFixture(URL + "?download=true");

        assertEquals(200, response.getStatus());
        assertTrue(response.getContentType().startsWith("application/json"));
        String header = response.getHeader("Content-Disposition");
        assertNotNull(header);
        assertTrue(header.contains("attachment"));
        assertTrue(header.contains("security-report-vulnerable-cluster.json"));

        assertExpectedVulnerableReport(mapper.readTree(response.getContentAsString()));
    }

    // ------------------------------------------------------------------
    // 6. RBAC scoping: RoleBinding -> ClusterRole stays namespace-scoped
    // ------------------------------------------------------------------

    @Test
    void roleBindingToClusterRoleIsNamespaceScoped() throws Exception {
        String body = """
                {
                  "clusterName": "scope-test",
                  "pods": [
                    {"uid": "p1", "name": "web", "namespace": "team-a",
                     "serviceAccountName": "app-sa"}
                  ],
                  "serviceAccounts": [
                    {"uid": "sa1", "name": "app-sa", "namespace": "team-a"}
                  ],
                  "clusterRoles": [
                    {"uid": "cr1", "name": "secret-reader",
                     "rules": [{"apiGroups": [""], "resources": ["secrets"],
                                "verbs": ["get"], "resourceNames": []}]}
                  ],
                  "roleBindings": [
                    {"uid": "rb1", "name": "rb", "namespace": "team-a",
                     "roleKind": "ClusterRole", "roleName": "secret-reader",
                     "subjects": [{"kind": "ServiceAccount", "name": "app-sa",
                                   "namespace": "team-a"}]}
                  ],
                  "secrets": [
                    {"uid": "s1", "name": "data-a", "namespace": "team-a", "secretType": "Opaque"},
                    {"uid": "s2", "name": "data-b", "namespace": "team-b", "secretType": "Opaque"}
                  ]
                }
                """;

        ClusterSnapshot snapshot = mapper.readValue(body, ClusterSnapshot.class);
        SecurityReport report = analysisService.analyze(pipeline.build(snapshot));

        // Only the secret in the binding's namespace is reachable.
        assertEquals(1, report.totalFindings());
        Finding f = report.findings().get(0);
        assertEquals("SECRET:team-a:data-a", f.target().getId());
        assertEquals(List.of("POD:team-a:web", "SERVICE_ACCOUNT:team-a:app-sa",
                        "ROLE_BINDING:team-a:rb", "SECRET:team-a:data-a"),
                nodeIds(f.attackPath()));

        // sensitivity 20 (Opaque, nothing sensitive) + scope 15 (RoleBinding)
        // + wildcard 0 + path 5 (3 edges) = 40 -> MEDIUM
        assertEquals(factors(20, 15, 0, 5), factorPoints(f.scoreFactors()));
        assertEquals(40, f.riskScore());
        assertEquals(Severity.MEDIUM, f.severity());
        assertTrue(f.recommendation().contains("RoleBinding's subjects"));
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    private void assertExpectedVulnerableReport(JsonNode root) {
        assertEquals("vulnerable-cluster", root.get("clusterName").textValue());
        String generatedAt = root.get("generatedAt").textValue();
        assertNotNull(generatedAt);
        assertDoesNotThrow(() -> Instant.parse(generatedAt));
        assertEquals(2, root.get("totalFindings").intValue());

        JsonNode counts = root.get("severityCounts");
        assertEquals(4, counts.size());
        assertEquals(0, counts.get("LOW").intValue());
        assertEquals(1, counts.get("MEDIUM").intValue());
        assertEquals(0, counts.get("HIGH").intValue());
        assertEquals(1, counts.get("CRITICAL").intValue());

        JsonNode findings = root.get("findings");
        assertEquals(2, findings.size());
        JsonNode critical = null;
        JsonNode medium = null;
        for (JsonNode f : findings) {
            switch (f.get("severity").textValue()) {
                case "CRITICAL" -> critical = f;
                case "MEDIUM" -> medium = f;
                default -> fail("Unexpected severity " + f.get("severity").textValue());
            }
        }
        assertNotNull(critical);
        assertNotNull(medium);

        assertJsonFinding(critical, 90, CRITICAL_PATH, factors(30, 30, 25, 5),
                "ClusterRoleBinding's subjects");
        assertJsonFinding(medium, 43, MEDIUM_PATH, factors(30, 10, 0, 3),
                "Role's rules");

        JsonNode crs = root.get("criticalResources");
        assertEquals(6, crs.size());
        Map<String, JsonNode> byId = new HashMap<>();
        for (JsonNode cr : crs) {
            byId.put(cr.get("resource").get("id").textValue(), cr);
        }
        assertJsonCritical(byId.get(CRB), 40, 1, 1);
        assertJsonCritical(byId.get(POD), 40, 1, 2);
        assertJsonCritical(byId.get(SA), 40, 1, 2);
        assertJsonCritical(byId.get(SECRET), 30, 0, 2);
        assertJsonCritical(byId.get(ROLE), 25, 1, 1);
        assertJsonCritical(byId.get(RB), 25, 1, 1);
        assertEquals(CRB, crs.get(0).get("resource").get("id").textValue());
    }

    private void assertJsonFinding(JsonNode f, int score, List<String> path,
                                   Map<String, Integer> factors, String recommendationFragment) {
        assertEquals(score, f.get("riskScore").intValue());
        assertEquals(POD, f.get("entryPoint").get("id").textValue());
        assertEquals(SECRET, f.get("target").get("id").textValue());
        assertEquals("SECRET", f.get("target").get("type").textValue());

        List<String> ids = new ArrayList<>();
        for (JsonNode n : f.get("attackPath")) {
            ids.add(n.get("id").textValue());
        }
        assertEquals(path, ids);

        Map<String, Integer> actual = new LinkedHashMap<>();
        int sum = 0;
        for (JsonNode sf : f.get("scoreFactors")) {
            actual.put(sf.get("name").textValue(), sf.get("points").intValue());
            sum += sf.get("points").intValue();
            assertFalse(sf.get("reason").textValue().isBlank());
        }
        assertEquals(factors, actual);
        assertEquals(new ArrayList<>(factors.keySet()), new ArrayList<>(actual.keySet()));
        assertEquals(score, Math.min(sum, 100));

        assertTrue(f.get("recommendation").textValue().contains(recommendationFragment));
        assertFalse(f.get("id").textValue().isBlank());
        assertFalse(f.get("title").textValue().isBlank());
    }

    private void assertJsonCritical(JsonNode cr, int score, int secrets, int findings) {
        assertNotNull(cr);
        assertEquals(score, cr.get("riskScore").intValue());
        assertEquals(secrets, cr.get("affectedSecretCount").intValue());
        assertEquals(findings, cr.get("findingCount").intValue());
        assertFalse(cr.get("reason").textValue().isBlank());
    }

    private MockHttpServletResponse postFixture(String url) throws Exception {
        return mockMvc.perform(post(url)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(Files.readString(FIXTURE)))
                .andReturn()
                .getResponse();
    }

    private static Finding findBySeverity(SecurityReport report, Severity severity) {
        List<Finding> matches = report.findings().stream()
                .filter(f -> f.severity() == severity).toList();
        assertEquals(1, matches.size(), "Expected exactly one " + severity + " finding");
        return matches.get(0);
    }

    private static List<String> nodeIds(List<GraphNode> nodes) {
        return nodes.stream().map(GraphNode::getId).toList();
    }

    private static Map<String, Integer> factors(int sensitivity, int scope,
                                                int wildcard, int pathLength) {
        Map<String, Integer> m = new LinkedHashMap<>();
        m.put("SECRET_SENSITIVITY", sensitivity);
        m.put("PERMISSION_SCOPE", scope);
        m.put("WILDCARD_PERMISSION", wildcard);
        m.put("ATTACK_PATH_LENGTH", pathLength);
        return m;
    }

    private static Map<String, Integer> factorPoints(List<ScoreFactor> factors) {
        Map<String, Integer> m = new LinkedHashMap<>();
        for (ScoreFactor f : factors) {
            m.put(f.name(), f.points());
        }
        return m;
    }
}