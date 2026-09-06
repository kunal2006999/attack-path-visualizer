package com.kunal.attackpathvisualizer.analysis;

import com.kunal.attackpathvisualizer.core.enums.ResourceType;
import com.kunal.attackpathvisualizer.graph.AttackGraph;
import com.kunal.attackpathvisualizer.graph.GraphNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class DFSAnalyzerTest {

    private AttackGraph graph;
    private DFSAnalyzer analyzer;

    @BeforeEach
    void setUp() {
        graph = GraphTestFixtures.createTestGraph();
        analyzer = new DFSAnalyzer(graph);
    }

    @Test
    void testNormalTraversal() {
        TraversalResult result = analyzer.dfs("Pod:default:my-pod");
        assertEquals("Pod:default:my-pod", result.getSource().getId());
        List<GraphNode> order = result.getTraversalOrder();
        assertTrue(order.size() >= 5);
        assertTrue(order.contains(graph.getNode("RoleBinding:default:my-rb")));
    }

    @Test
    void testDisconnectedComponents() {
        TraversalResult result = analyzer.dfs("Pod:default:iso-pod");
        List<GraphNode> order = result.getTraversalOrder();
        assertEquals(2, order.size());
        assertTrue(order.contains(graph.getNode("Pod:default:iso-pod")));
        assertTrue(order.contains(graph.getNode("ServiceAccount:default:iso-sa")));
        assertFalse(order.contains(graph.getNode("Pod:default:my-pod")));
    }

    @Test
    void testSourceOnlyGraph() {
        AttackGraph emptyGraph = new AttackGraph();
        GraphNode node = new GraphNode("Node1", "uid1", ResourceType.POD, "Node1", "default");
        emptyGraph.addNode(node);
        DFSAnalyzer emptyAnalyzer = new DFSAnalyzer(emptyGraph);

        TraversalResult result = emptyAnalyzer.dfs("Node1");
        assertEquals(1, result.getTraversalOrder().size());
        assertEquals("Node1", result.getTraversalOrder().get(0).getId());
    }

    @Test
    void testInvalidSourceId() {
        assertThrows(IllegalArgumentException.class, () -> analyzer.dfs("NonExistent"));
    }

    @Test
    void testTraversalVisitsEveryReachableNode() {
        TraversalResult result = analyzer.dfs("Pod:default:my-pod");
        List<GraphNode> order = result.getTraversalOrder();
        
        assertTrue(order.contains(graph.getNode("Pod:default:my-pod")));
        assertTrue(order.contains(graph.getNode("ServiceAccount:default:my-sa")));
        assertTrue(order.contains(graph.getNode("RoleBinding:default:my-rb")));
        assertTrue(order.contains(graph.getNode("Role:default:my-role")));
        assertTrue(order.contains(graph.getNode("Secret:default:my-secret")));
    }
}
