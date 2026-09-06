package com.kunal.attackpathvisualizer.analysis;

import com.kunal.attackpathvisualizer.core.enums.ResourceType;
import com.kunal.attackpathvisualizer.core.relation.RelationshipType;
import com.kunal.attackpathvisualizer.graph.AttackGraph;
import com.kunal.attackpathvisualizer.graph.GraphEdge;
import com.kunal.attackpathvisualizer.graph.GraphNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class DijkstraAnalyzerTest {

    private AttackGraph graph;
    private DijkstraAnalyzer analyzer;

    @BeforeEach
    void setUp() {
        graph = GraphTestFixtures.createTestGraph();
        analyzer = new DijkstraAnalyzer(graph);
    }

    @Test
    void testShortestDistancesBasic() {
        DijkstraResult result = analyzer.shortestDistances("Pod:default:my-pod");
        Map<GraphNode, Integer> distances = result.getDistances();
        
        assertEquals(0, distances.get(graph.getNode("Pod:default:my-pod")));
        assertEquals(1, distances.get(graph.getNode("ServiceAccount:default:my-sa")));
        assertEquals(2, distances.get(graph.getNode("RoleBinding:default:my-rb")));
        assertEquals(3, distances.get(graph.getNode("Role:default:my-role")));
        
        // Multi-hop path cost: SA -> RB -> Role -> Secret (1+1+1+1 = 4)
        // Direct path cost: SA -> Secret (1+5 = 6)
        // So shortest is 4
        assertEquals(4, distances.get(graph.getNode("Secret:default:my-secret")));
    }

    @Test
    void testWeightedEdgesRespected() {
        AttackGraph weighted = new AttackGraph();
        GraphNode n1 = new GraphNode("n1", "1", ResourceType.POD, "n1", "default");
        GraphNode n2 = new GraphNode("n2", "2", ResourceType.POD, "n2", "default");
        GraphNode n3 = new GraphNode("n3", "3", ResourceType.POD, "n3", "default");
        weighted.addNode(n1);
        weighted.addNode(n2);
        weighted.addNode(n3);
        
        weighted.addEdge(new GraphEdge(n1, n2, RelationshipType.USES, 10)); // direct is expensive
        weighted.addEdge(new GraphEdge(n1, n3, RelationshipType.USES, 2));
        weighted.addEdge(new GraphEdge(n3, n2, RelationshipType.USES, 3)); // indirect is cheaper
        
        DijkstraAnalyzer wa = new DijkstraAnalyzer(weighted);
        DijkstraResult result = wa.shortestDistances("n1");
        
        assertEquals(5, result.getDistances().get(n2), "Should prefer multi-hop cheaper route");
        assertEquals(n3, result.getPrevious().get(n2));
    }

    @Test
    void testUnreachableNodes() {
        DijkstraResult result = analyzer.shortestDistances("Pod:default:my-pod");
        Map<GraphNode, Integer> distances = result.getDistances();
        
        assertNull(distances.get(graph.getNode("Pod:default:iso-pod")), "Unreachable node should not have a distance");
    }

    @Test
    void testInvalidSourceId() {
        assertThrows(IllegalArgumentException.class, () -> analyzer.shortestDistances("NonExistent"));
    }
}
