package com.kunal.attackpathvisualizer.graph;

import com.kunal.attackpathvisualizer.core.enums.ResourceType;
import com.kunal.attackpathvisualizer.core.relation.RelationshipType;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AttackGraphTest {

    @Test
    void shouldAddAndGetNode() {

        AttackGraph graph = new AttackGraph();

        GraphNode pod = new GraphNode(
                "pod:production:backend",
                "pod-001",
                ResourceType.POD,
                "backend",
                "production"
        );

        graph.addNode(pod);

        assertEquals(1, graph.getNodeCount());
        assertSame(pod, graph.getNode("pod:production:backend"));
    }

    @Test
    void shouldPreventDuplicateNodes() {

        AttackGraph graph = new AttackGraph();

        GraphNode pod = new GraphNode(
                "pod:production:backend",
                "pod-001",
                ResourceType.POD,
                "backend",
                "production"
        );

        graph.addNode(pod);
        graph.addNode(pod);

        assertEquals(1, graph.getNodeCount());
    }

    @Test
    void shouldAddEdgeAndFindNeighbor() {

        AttackGraph graph = new AttackGraph();

        GraphNode pod = new GraphNode(
                "pod:production:backend",
                "pod-001",
                ResourceType.POD,
                "backend",
                "production"
        );

        GraphNode serviceAccount = new GraphNode(
                "sa:production:backend",
                "sa-001",
                ResourceType.SERVICE_ACCOUNT,
                "backend-sa",
                "production"
        );

        GraphEdge edge = new GraphEdge(
                pod,
                serviceAccount,
                RelationshipType.USES
        );

        graph.addEdge(edge);

        assertEquals(2, graph.getNodeCount());
        assertEquals(1, graph.getEdgeCount());

        assertEquals(
                serviceAccount,
                graph.getNeighbors("pod:production:backend").get(0)
        );
    }

    @Test
    void shouldRemoveNodeAndItsEdges() {

        AttackGraph graph = new AttackGraph();

        GraphNode pod = new GraphNode(
                "pod:production:backend",
                "pod-001",
                ResourceType.POD,
                "backend",
                "production"
        );

        GraphNode serviceAccount = new GraphNode(
                "sa:production:backend",
                "sa-001",
                ResourceType.SERVICE_ACCOUNT,
                "backend-sa",
                "production"
        );

        graph.addEdge(
                new GraphEdge(
                        pod,
                        serviceAccount,
                        RelationshipType.USES
                )
        );

        assertEquals(2, graph.getNodeCount());
        assertEquals(1, graph.getEdgeCount());

        graph.removeNode("pod:production:backend");

        assertEquals(1, graph.getNodeCount());
        assertEquals(0, graph.getEdgeCount());

        assertNull(
                graph.getNode("pod:production:backend")
        );

        assertTrue(
                graph.getNeighbors("sa:production:backend").isEmpty()
        );
    }

    @Test
    void shouldPreventDuplicateEdges() {

        AttackGraph graph = new AttackGraph();

        GraphNode pod = new GraphNode(
                "pod:production:backend",
                "pod-001",
                ResourceType.POD,
                "backend",
                "production"
        );

        GraphNode serviceAccount = new GraphNode(
                "sa:production:backend",
                "sa-001",
                ResourceType.SERVICE_ACCOUNT,
                "backend-sa",
                "production"
        );

        GraphEdge edge = new GraphEdge(
                pod,
                serviceAccount,
                RelationshipType.USES
        );

        graph.addEdge(edge);
        graph.addEdge(edge);

        assertEquals(1, graph.getEdgeCount());
    }


}
