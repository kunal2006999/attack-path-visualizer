package com.kunal.attackpathvisualizer.report;

import com.kunal.attackpathvisualizer.core.enums.ResourceType;
import com.kunal.attackpathvisualizer.graph.GraphNode;
import com.kunal.attackpathvisualizer.security.CriticalResource;
import com.kunal.attackpathvisualizer.security.Finding;
import com.kunal.attackpathvisualizer.security.ScoreFactor;
import com.kunal.attackpathvisualizer.security.SecurityReport;
import com.kunal.attackpathvisualizer.security.Severity;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class SecurityReportExporterTest {

    private final SecurityReportExporter exporter = new SecurityReportExporter();
    private final ObjectMapper mapper = new ObjectMapper();

    private static GraphNode node(String id, String uid, ResourceType type,
                                  String name, String ns) {
        return new GraphNode(id, uid, type, name, ns);
    }

    private SecurityReport sampleReport() {
        GraphNode pod = node("POD:default:p", "pod-1", ResourceType.POD, "p", "default");
        GraphNode rb = node("ROLE_BINDING:default:rb", "rb-1", ResourceType.ROLE_BINDING, "rb", "default");
        GraphNode secret = node("SECRET:default:s", "s-1", ResourceType.SECRET, "s", "default");

        Finding finding = new Finding(
                "f-1",
                "Pod can reach Secret: s",
                "Modeled path description.",
                pod,
                secret,
                List.of(pod, rb, secret),
                20,
                Severity.LOW,
                List.of(new ScoreFactor("SECRET_SENSITIVITY", 20, "Base sensitivity")),
                "Review the grant."
        );

        CriticalResource critical = new CriticalResource(
                rb, 45, 1, 1, "Appears in 1 security finding(s)");

        return new SecurityReport(
                Instant.parse("2026-01-01T00:00:00Z"),
                1,
                Map.of(Severity.LOW, 1),
                List.of(finding),
                List.of(critical)
        );
    }

    @Test
    void producesValidJsonWithTopLevelFields() throws Exception {
        JsonNode root = mapper.readTree(exporter.export("demo", sampleReport()));

        assertEquals("demo", root.get("clusterName").textValue());
        assertEquals("2026-01-01T00:00:00Z", root.get("generatedAt").textValue());
        assertEquals(1, root.get("totalFindings").intValue());
        assertTrue(root.get("severityCounts").isObject());
        assertTrue(root.get("findings").isArray());
        assertTrue(root.get("criticalResources").isArray());
    }

    @Test
    void includesAllSeverityCategoriesEvenWhenZero() throws Exception {
        JsonNode counts = mapper
                .readTree(exporter.export(sampleReport()))
                .get("severityCounts");

        assertEquals(4, counts.size());
        assertEquals(1, counts.get("LOW").intValue());
        assertEquals(0, counts.get("MEDIUM").intValue());
        assertEquals(0, counts.get("HIGH").intValue());
        assertEquals(0, counts.get("CRITICAL").intValue());
    }

    @Test
    void emptyReportHasAllSeveritiesAtZero() throws Exception {
        SecurityReport empty = new SecurityReport(
                Instant.parse("2026-01-01T00:00:00Z"),
                0, Map.of(), List.of(), List.of());

        JsonNode root = mapper.readTree(exporter.export("empty", empty));

        assertEquals(0, root.get("totalFindings").intValue());
        assertEquals(4, root.get("severityCounts").size());
        for (Severity s : Severity.values()) {
            assertEquals(0, root.get("severityCounts").get(s.name()).intValue());
        }
        assertEquals(0, root.get("findings").size());
        assertEquals(0, root.get("criticalResources").size());
    }

    @Test
    void preservesFindingDetails() throws Exception {
        JsonNode finding = mapper
                .readTree(exporter.export(sampleReport()))
                .get("findings").get(0);

        assertEquals("f-1", finding.get("id").textValue());
        assertEquals("Pod can reach Secret: s", finding.get("title").textValue());
        assertEquals("Modeled path description.", finding.get("description").textValue());
        assertEquals(20, finding.get("riskScore").intValue());
        assertEquals("LOW", finding.get("severity").textValue());
        assertEquals("Review the grant.", finding.get("recommendation").textValue());

        assertEquals("p", finding.get("entryPoint").get("name").textValue());
        assertEquals("POD", finding.get("entryPoint").get("type").textValue());
        assertEquals("SECRET", finding.get("target").get("type").textValue());

        JsonNode path = finding.get("attackPath");
        assertEquals(3, path.size());
        assertEquals("POD:default:p", path.get(0).get("id").textValue());
        assertEquals("ROLE_BINDING:default:rb", path.get(1).get("id").textValue());
        assertEquals("SECRET:default:s", path.get(2).get("id").textValue());

        JsonNode factor = finding.get("scoreFactors").get(0);
        assertEquals("SECRET_SENSITIVITY", factor.get("name").textValue());
        assertEquals(20, factor.get("points").intValue());
        assertEquals("Base sensitivity", factor.get("reason").textValue());
    }

    @Test
    void preservesCriticalResources() throws Exception {
        JsonNode cr = mapper
                .readTree(exporter.export(sampleReport()))
                .get("criticalResources").get(0);

        assertEquals("rb", cr.get("resource").get("name").textValue());
        assertEquals(45, cr.get("riskScore").intValue());
        assertEquals(1, cr.get("affectedSecretCount").intValue());
        assertEquals(1, cr.get("findingCount").intValue());
        assertEquals("Appears in 1 security finding(s)", cr.get("reason").textValue());
    }

    @Test
    void clusterScopedNodeSerializesNullNamespace() throws Exception {
        GraphNode crb = node("CLUSTER_ROLE_BINDING:crb", "crb-1",
                ResourceType.CLUSTER_ROLE_BINDING, "crb", null);
        SecurityReport report = new SecurityReport(
                Instant.parse("2026-01-01T00:00:00Z"),
                0, Map.of(), List.of(),
                List.of(new CriticalResource(crb, 15, 0, 0, "ClusterRoleBinding")));

        JsonNode resource = mapper
                .readTree(exporter.export("c", report))
                .get("criticalResources").get(0).get("resource");

        assertTrue(resource.get("namespace").isNull());
        assertEquals("CLUSTER_ROLE_BINDING", resource.get("type").textValue());
    }

    @Test
    void rejectsNullReport() {
        assertThrows(NullPointerException.class, () -> exporter.export("c", null));
    }
}