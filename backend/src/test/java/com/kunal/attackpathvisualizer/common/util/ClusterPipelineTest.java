package com.kunal.attackpathvisualizer.common.util;

import com.kunal.attackpathvisualizer.common.model.snapshot.ClusterSnapshot;
import com.kunal.attackpathvisualizer.core.builder.ClusterSnapshotMapper;
import com.kunal.attackpathvisualizer.core.model.Cluster;
import com.kunal.attackpathvisualizer.core.relation.RelationshipType;
import com.kunal.attackpathvisualizer.core.validation.ClusterSnapshotValidator;
import com.kunal.attackpathvisualizer.graph.AttackGraph;
import com.kunal.attackpathvisualizer.graph.GraphBuilder;
import com.kunal.attackpathvisualizer.graph.GraphNode;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class ClusterPipelineTest {

    private final ClusterSnapshotParser parser =
            new ClusterSnapshotParser();

    private final ClusterSnapshotValidator validator =
            new ClusterSnapshotValidator();

    private final ClusterSnapshotMapper mapper =
            new ClusterSnapshotMapper();

    private final GraphBuilder graphBuilder =
            new GraphBuilder();

    @Test
    void shouldConvertJsonToAttackGraph() throws IOException {

        Path file = Path.of(
                "sample-data",
                "clusters",
                "simple-cluster.json"
        );

        ClusterSnapshotParser parser =
                new ClusterSnapshotParser();

        ClusterSnapshot snapshot =
                parser.parse(file);

        new ClusterSnapshotValidator()
                .validate(snapshot);

        Cluster cluster =
                new ClusterSnapshotMapper()
                        .map(snapshot);

        AttackGraph graph =
                new GraphBuilder()
                        .build(cluster);

        assertNotNull(snapshot);
        assertNotNull(cluster);
        assertNotNull(graph);

        assertEquals(
                snapshot.getClusterName(),
                cluster.getName()
        );

        assertEquals(
                cluster.getResources().size(),
                graph.getNodeCount()
        );
    }

    @Test
    void shouldBuildSecretAccessChain() {

        AttackGraph graph = buildGraph(
                "vulnerable-cluster.json"
        );

        GraphNode serviceAccount = graph.getNode(
                "SERVICE_ACCOUNT:production:backend-sa"
        );

        GraphNode roleBinding = graph.getNode(
                "ROLE_BINDING:production:backend-secret-reader"
        );

        GraphNode role = graph.getNode(
                "ROLE:production:secret-reader"
        );

        GraphNode secret = graph.getNode(
                "SECRET:production:database-secret"
        );

        assertNotNull(serviceAccount);
        assertNotNull(roleBinding);
        assertNotNull(role);
        assertNotNull(secret);

        assertTrue(
                graph.getOutgoingEdges(serviceAccount.getId())
                        .stream()
                        .anyMatch(edge ->
                                edge.getTarget().getId()
                                        .equals(roleBinding.getId())
                                        && edge.getRelationshipType()
                                        == RelationshipType.HAS_BINDING
                        )
        );

        assertTrue(
                graph.getOutgoingEdges(roleBinding.getId())
                        .stream()
                        .anyMatch(edge ->
                                edge.getTarget().getId()
                                        .equals(role.getId())
                                        && edge.getRelationshipType()
                                        == RelationshipType.GRANTS
                        )
        );

        assertTrue(
                graph.getOutgoingEdges(role.getId())
                        .stream()
                        .anyMatch(edge ->
                                edge.getTarget().getId()
                                        .equals(secret.getId())
                                        && edge.getRelationshipType()
                                        == RelationshipType.CAN_ACCESS
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