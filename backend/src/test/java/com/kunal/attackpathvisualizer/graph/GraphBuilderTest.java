package com.kunal.attackpathvisualizer.graph;

import com.kunal.attackpathvisualizer.core.builder.MockClusterBuilder;
import com.kunal.attackpathvisualizer.core.model.Cluster;
import com.kunal.attackpathvisualizer.core.relation.RelationshipType;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class GraphBuilderTest {
    @Test
    void shouldBuildGraphFromMockCluster() {

        Cluster cluster = MockClusterBuilder.build();

        GraphBuilder graphBuilder = new GraphBuilder();

        AttackGraph graph = graphBuilder.build(cluster);

        assertNotNull(graph);

        assertEquals(
                cluster.getResources().size(),
                graph.getNodeCount()
        );

        assertEquals(
                cluster.getRelationships().size(),
                graph.getEdgeCount()
        );
    }

    @Test
    void shouldCreateExpectedGraphNodes() {

        Cluster cluster = MockClusterBuilder.build();

        AttackGraph graph = new GraphBuilder().build(cluster);

        GraphNode pod = graph.getNode(
                "POD:production:backend-pod"
        );

        GraphNode serviceAccount = graph.getNode(
                "SERVICE_ACCOUNT:production:backend-sa"
        );

        GraphNode secret = graph.getNode(
                "SECRET:production:database-secret"
        );

        assertNotNull(pod);
        assertNotNull(serviceAccount);
        assertNotNull(secret);

        assertEquals("pod-001", pod.getResourceId());
        assertEquals("backend-pod", pod.getName());
        assertEquals("production", pod.getNamespace());
    }

    @Test
    void shouldCreateExpectedGraphEdges() {

        Cluster cluster = MockClusterBuilder.build();

        AttackGraph graph = new GraphBuilder().build(cluster);

        GraphNode pod = graph.getNode(
                "POD:production:backend-pod"
        );

        GraphNode serviceAccount = graph.getNode(
                "SERVICE_ACCOUNT:production:backend-sa"
        );

        GraphNode secret = graph.getNode(
                "SECRET:production:database-secret"
        );

        GraphNode role = graph.getNode(
                "ROLE:production:backend-reader"
        );

        GraphNode roleBinding = graph.getNode(
                "ROLE_BINDING:production:backend-binding"
        );

        assertTrue(
                graph.getOutgoingEdges(pod.getId())
                        .stream()
                        .anyMatch(edge ->
                                edge.getTarget().getId()
                                        .equals(serviceAccount.getId())
                                        && edge.getRelationshipType()
                                        == RelationshipType.USES
                        )
        );

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
}
