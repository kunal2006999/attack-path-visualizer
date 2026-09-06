package com.kunal.attackpathvisualizer.analysis;

import com.kunal.attackpathvisualizer.core.enums.ResourceType;
import com.kunal.attackpathvisualizer.graph.AttackGraph;
import com.kunal.attackpathvisualizer.graph.GraphNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class BFSAnalyzerTest {

    private AttackGraph graph;
    private BFSAnalyzer analyzer;

    @BeforeEach
    void setUp() {
        graph = GraphTestFixtures.createTestGraph();
        analyzer = new BFSAnalyzer(graph);
    }

    @Test
    void testNormalTraversal() {
        TraversalResult result = analyzer.bfs("Pod:default:my-pod");
        assertEquals("Pod:default:my-pod", result.getSource().getId());
        List<GraphNode> order = result.getTraversalOrder();
        assertTrue(order.size() >= 5);
        assertEquals("Pod:default:my-pod", order.get(0).getId());
    }

    @Test
    void testDisconnectedComponents() {
        TraversalResult result = analyzer.bfs("Pod:default:iso-pod");
        List<GraphNode> order = result.getTraversalOrder();
        assertEquals(2, order.size());
        assertTrue(order.stream().anyMatch(n -> n.getId().equals("Pod:default:iso-pod")));
        assertTrue(order.stream().anyMatch(n -> n.getId().equals("ServiceAccount:default:iso-sa")));
        assertFalse(order.stream().anyMatch(n -> n.getId().equals("Pod:default:my-pod")));
    }

    @Test
    void testSourceOnlyGraph() {
        AttackGraph emptyGraph = new AttackGraph();
        GraphNode node = new GraphNode("Node1", "uid1", ResourceType.POD, "Node1", "default");
        emptyGraph.addNode(node);
        BFSAnalyzer emptyAnalyzer = new BFSAnalyzer(emptyGraph);

        TraversalResult result = emptyAnalyzer.bfs("Node1");
        assertEquals(1, result.getTraversalOrder().size());
        assertEquals("Node1", result.getTraversalOrder().get(0).getId());
        assertEquals(node, result.getSource());
    }

    @Test
    void testInvalidSourceId() {
        assertThrows(IllegalArgumentException.class, () -> analyzer.bfs("NonExistentNode"));
    }

    @Test
    void testVerifyTraversalOrder() {
        TraversalResult result = analyzer.bfs("Pod:default:my-pod");
        List<GraphNode> order = result.getTraversalOrder();
        int podIdx = order.indexOf(graph.getNode("Pod:default:my-pod"));
        int saIdx = order.indexOf(graph.getNode("ServiceAccount:default:my-sa"));
        int rbIdx = order.indexOf(graph.getNode("RoleBinding:default:my-rb"));
        int secretIdx = order.indexOf(graph.getNode("Secret:default:my-secret"));

        assertTrue(podIdx < saIdx);
        assertTrue(saIdx < rbIdx);
        // BFS means sa should be visited before secret, but secret is neighbor of sa as well
        // So secret should be visited after sa.
        assertTrue(saIdx < secretIdx);
    }
}
