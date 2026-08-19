package com.kunal.attackpathvisualizer.graph;

import com.kunal.attackpathvisualizer.core.builder.MockClusterBuilder;
import com.kunal.attackpathvisualizer.core.model.Cluster;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class GraphJsonExporterTest {
    @Test
    void shouldExportGraphAsJson() {

        Cluster cluster = MockClusterBuilder.build();

        AttackGraph graph = new GraphBuilder().build(cluster);

        GraphJsonExporter exporter = new GraphJsonExporter();

        String json = exporter.export(graph);

        assertNotNull(json);
        assertTrue(json.contains("\"nodes\""));
        assertTrue(json.contains("\"edges\""));
        assertTrue(json.contains("backend-pod"));
        assertTrue(json.contains("backend-sa"));
        assertTrue(json.contains("USES"));
    }
}
