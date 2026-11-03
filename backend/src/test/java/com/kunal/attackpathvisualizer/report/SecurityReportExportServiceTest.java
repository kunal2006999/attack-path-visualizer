package com.kunal.attackpathvisualizer.report;

import com.kunal.attackpathvisualizer.common.exception.InvalidClusterSnapshotException;
import com.kunal.attackpathvisualizer.common.model.snapshot.ClusterSnapshot;
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
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class SecurityReportExportServiceTest {

    private final ClusterSnapshotParser parser = new ClusterSnapshotParser();
    private final ObjectMapper mapper = new ObjectMapper();

    private final SecurityReportExportService service =
            new SecurityReportExportService(
                    new ClusterGraphPipeline(
                            parser,
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

    private ClusterSnapshot load(String file) throws IOException {
        return parser.parse(Path.of("sample-data", "clusters", file));
    }

    @Test
    void exportsVulnerableClusterReport() throws Exception {
        var exported = service.export(load("vulnerable-cluster.json"));

        assertEquals("vulnerable-cluster", exported.clusterName());
        assertEquals(2, exported.report().totalFindings());

        JsonNode root = mapper.readTree(exported.json());
        assertEquals("vulnerable-cluster", root.get("clusterName").textValue());
        assertEquals(2, root.get("totalFindings").intValue());
        assertEquals(2, root.get("findings").size());
        assertEquals(4, root.get("severityCounts").size());
        assertFalse(root.get("criticalResources").isEmpty());
    }

    @Test
    void exportsIsolatedClusterWithZeroFindings() throws Exception {
        var exported = service.export(load("isolated-resources.json"));

        JsonNode root = mapper.readTree(exported.json());
        assertEquals(0, root.get("totalFindings").intValue());
        assertEquals(4, root.get("severityCounts").size());
        assertEquals(0, root.get("findings").size());
    }

    @Test
    void rejectsNullSnapshot() {
        assertThrows(InvalidClusterSnapshotException.class,
                () -> service.export(null));
    }

    @Test
    void rejectsInvalidSnapshot() {
        // No cluster name -> validator throws IllegalArgumentException.
        assertThrows(InvalidClusterSnapshotException.class,
                () -> service.export(new ClusterSnapshot()));
    }
}