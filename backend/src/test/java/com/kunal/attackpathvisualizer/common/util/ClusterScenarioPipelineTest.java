package com.kunal.attackpathvisualizer.common.util;

import com.kunal.attackpathvisualizer.common.model.snapshot.ClusterSnapshot;
import com.kunal.attackpathvisualizer.core.builder.ClusterSnapshotMapper;
import com.kunal.attackpathvisualizer.core.builder.MockClusterBuilder;
import com.kunal.attackpathvisualizer.core.model.Cluster;
import com.kunal.attackpathvisualizer.core.validation.ClusterSnapshotValidator;
import com.kunal.attackpathvisualizer.graph.AttackGraph;
import com.kunal.attackpathvisualizer.graph.GraphBuilder;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class ClusterScenarioPipelineTest {

    private final ClusterSnapshotParser parser =
            new ClusterSnapshotParser();

    private final ClusterSnapshotValidator validator =
            new ClusterSnapshotValidator();

    private final ClusterSnapshotMapper mapper =
            new ClusterSnapshotMapper();

    private final GraphBuilder graphBuilder =
            new GraphBuilder();

    @Test
    void shouldBuildVulnerableClusterGraph() {

        AttackGraph graph = buildGraph(
                "vulnerable-cluster.json"
        );

        assertTrue(graph.getNodeCount() > 0);
        assertTrue(graph.getEdgeCount() > 0);

        assertNotNull(
                graph.getNode(
                        "POD:production:backend-pod"
                )
        );

        assertNotNull(
                graph.getNode(
                        "SERVICE_ACCOUNT:production:backend-sa"
                )
        );

        assertNotNull(
                graph.getNode(
                        "SECRET:production:database-secret"
                )
        );
    }

    @Test
    void shouldBuildMultiPathClusterGraph() {

        AttackGraph graph = buildGraph(
                "multi-path-cluster.json"
        );

        assertTrue(graph.getNodeCount() > 0);
        assertTrue(graph.getEdgeCount() > 0);

        assertNotNull(
                graph.getNode(
                        "ROLE:production:secret-a-reader"
                )
        );

        assertNotNull(
                graph.getNode(
                        "ROLE:production:secret-b-reader"
                )
        );
    }

    @Test
    void shouldBuildIsolatedClusterGraph() {

        AttackGraph graph = buildGraph(
                "isolated-resources.json"
        );

        assertNotNull(
                graph.getNode(
                        "POD:production:isolated-pod"
                )
        );

        assertNotNull(
                graph.getNode(
                        "SERVICE_ACCOUNT:production:isolated-sa"
                )
        );
    }

    private AttackGraph buildGraph(String fileName) {

        Path file = Path.of(
                "sample-data",
                "clusters",
                fileName
        );

        ClusterSnapshot snapshot;

        try {
            snapshot = parser.parse(file);
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Could not load " + fileName,
                    e
            );
        }

        validator.validate(snapshot);

        Cluster cluster = mapper.map(snapshot);

        return graphBuilder.build(cluster);
    }
}