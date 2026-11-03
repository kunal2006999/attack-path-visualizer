package com.kunal.attackpathvisualizer.report;

import com.kunal.attackpathvisualizer.common.exception.GlobalExceptionHandler;
import com.kunal.attackpathvisualizer.common.util.ClusterSnapshotParser;
import com.kunal.attackpathvisualizer.core.builder.ClusterSnapshotMapper;
import com.kunal.attackpathvisualizer.core.pipeline.ClusterGraphPipeline;
import com.kunal.attackpathvisualizer.core.validation.ClusterSnapshotValidator;
import com.kunal.attackpathvisualizer.graph.GraphBuilder;
import com.kunal.attackpathvisualizer.security.AttackPathAnalyzer;
import com.kunal.attackpathvisualizer.security.CriticalResourceAnalyzer;
import com.kunal.attackpathvisualizer.security.RecommendationEngine;
import com.kunal.attackpathvisualizer.security.RiskScorer;
import com.kunal.attackpathvisualizer.security.SecretSensitivityClassifier;
import com.kunal.attackpathvisualizer.security.SecurityAnalysisService;
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

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * End-to-end controller tests (real pipeline + analysis) without a Spring context.
 */
class SecurityReportControllerTest {

    private static final String URL = "/api/security/reports/export";

    private final ObjectMapper mapper = new ObjectMapper();
    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        SecurityReportExportService service = new SecurityReportExportService(
                new ClusterGraphPipeline(
                        new ClusterSnapshotParser(),
                        new ClusterSnapshotValidator(),
                        new ClusterSnapshotMapper(),
                        new GraphBuilder()),
                new SecurityAnalysisService(
                        new AttackPathAnalyzer(
                                new SecretSensitivityClassifier(),
                                new RiskScorer()),
                        new CriticalResourceAnalyzer(),
                        new RecommendationEngine()),
                new SecurityReportExporter());

        mockMvc = MockMvcBuilders
                .standaloneSetup(new SecurityReportController(service))
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    private String fixture(String name) throws Exception {
        return Files.readString(Path.of("sample-data", "clusters", name));
    }

    private MockHttpServletResponse postJson(String url, String body) throws Exception {
        return mockMvc.perform(post(url)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andReturn()
                .getResponse();
    }

    private void assertJsonContentType(MockHttpServletResponse response) {
        assertNotNull(response.getContentType());
        assertTrue(response.getContentType().startsWith("application/json"),
                "Unexpected content type: " + response.getContentType());
    }

    @Test
    void validSnapshotReturnsReport() throws Exception {
        MockHttpServletResponse response =
                postJson(URL, fixture("vulnerable-cluster.json"));

        assertEquals(200, response.getStatus());
        assertJsonContentType(response);
        assertNull(response.getHeader("Content-Disposition"));

        JsonNode root = mapper.readTree(response.getContentAsString());
        assertEquals("vulnerable-cluster", root.get("clusterName").textValue());
        assertEquals(2, root.get("totalFindings").intValue());
        assertEquals(2, root.get("findings").size());
        assertEquals(4, root.get("severityCounts").size());

        int sum = 0;
        for (String severity : new String[]{"LOW", "MEDIUM", "HIGH", "CRITICAL"}) {
            assertTrue(root.get("severityCounts").has(severity));
            sum += root.get("severityCounts").get(severity).intValue();
        }
        assertEquals(2, sum);

        JsonNode finding = root.get("findings").get(0);
        assertFalse(finding.get("attackPath").isEmpty());
        assertFalse(finding.get("scoreFactors").isEmpty());
        assertFalse(finding.get("recommendation").textValue().isBlank());
    }

    @Test
    void isolatedClusterReturnsZeroCountsForAllSeverities() throws Exception {
        MockHttpServletResponse response =
                postJson(URL, fixture("isolated-resources.json"));

        assertEquals(200, response.getStatus());
        JsonNode counts = mapper.readTree(response.getContentAsString())
                .get("severityCounts");
        assertEquals(4, counts.size());
        assertEquals(0, counts.get("CRITICAL").intValue());
    }

    @Test
    void downloadParameterAddsContentDisposition() throws Exception {
        MockHttpServletResponse response =
                postJson(URL + "?download=true", fixture("vulnerable-cluster.json"));

        assertEquals(200, response.getStatus());
        String header = response.getHeader("Content-Disposition");
        assertNotNull(header);
        assertTrue(header.contains("attachment"));
        assertTrue(header.contains("security-report-vulnerable-cluster.json"));
    }

    @Test
    void malformedJsonReturnsBadRequest() throws Exception {
        MockHttpServletResponse response = postJson(URL, "{ this is not json");

        assertEquals(400, response.getStatus());
        JsonNode error = mapper.readTree(response.getContentAsString());
        assertEquals(400, error.get("status").intValue());
        assertFalse(error.get("message").textValue().isBlank());
    }

    @Test
    void emptyBodyReturnsBadRequest() throws Exception {
        MockHttpServletResponse response = postJson(URL, "");

        assertEquals(400, response.getStatus());
        JsonNode error = mapper.readTree(response.getContentAsString());
        assertEquals(400, error.get("status").intValue());
    }

    @Test
    void emptyObjectFailsSnapshotValidation() throws Exception {
        MockHttpServletResponse response = postJson(URL, "{}");

        assertEquals(400, response.getStatus());
        JsonNode error = mapper.readTree(response.getContentAsString());
        assertTrue(error.get("message").textValue().toLowerCase().contains("cluster name"));
    }

    @Test
    void duplicateUidsReturnBadRequest() throws Exception {
        String body = """
                {
                  "clusterName": "dup",
                  "pods": [
                    {"uid": "u-1", "name": "a", "namespace": "ns"},
                    {"uid": "u-1", "name": "b", "namespace": "ns"}
                  ]
                }
                """;

        MockHttpServletResponse response = postJson(URL, body);

        assertEquals(400, response.getStatus());
        JsonNode error = mapper.readTree(response.getContentAsString());
        assertTrue(error.get("message").textValue().contains("Duplicate"));
    }

    @Test
    void unsupportedContentTypeReturns415() throws Exception {
        MockHttpServletResponse response = mockMvc.perform(post(URL)
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("hello"))
                .andReturn()
                .getResponse();

        assertEquals(415, response.getStatus());
    }
}