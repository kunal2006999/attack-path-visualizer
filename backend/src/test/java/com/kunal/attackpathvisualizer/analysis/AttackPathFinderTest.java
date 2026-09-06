package com.kunal.attackpathvisualizer.analysis;

import com.kunal.attackpathvisualizer.core.enums.ResourceType;
import com.kunal.attackpathvisualizer.core.relation.RelationshipType;
import com.kunal.attackpathvisualizer.graph.AttackGraph;
import com.kunal.attackpathvisualizer.graph.GraphEdge;
import com.kunal.attackpathvisualizer.graph.GraphNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class AttackPathFinderTest {

    private AttackGraph graph;
    private AttackPathFinder finder;

    @BeforeEach
    void setUp() {
        graph = GraphTestFixtures.createTestGraph();
        finder = new AttackPathFinder(graph);
    }

    @Test
    void testShortestPathNormal() {
        AttackPathResult result = finder.findShortestPath("Pod:default:my-pod", "Secret:default:my-secret");
        
        assertEquals("Pod:default:my-pod", result.getSource().getId());
        assertEquals("Secret:default:my-secret", result.getTarget().getId());
        
        List<GraphNode> path = result.getNodes();
        // Path: Pod -> SA -> RB -> Role -> Secret
        assertEquals(5, path.size());
        assertEquals("Pod:default:my-pod", path.get(0).getId());
        assertEquals("Secret:default:my-secret", path.get(4).getId());
        assertEquals(4, result.getTotalCost());
    }

    @Test
    void testMultiplePossiblePaths() {
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
        
        AttackPathFinder pf = new AttackPathFinder(weighted);
        AttackPathResult result = pf.findShortestPath("n1", "n2");
        
        assertEquals(5, result.getTotalCost());
        List<GraphNode> path = result.getNodes();
        assertEquals(3, path.size());
        assertEquals("n3", path.get(1).getId());
    }

    @Test
    void testDisconnectedSourceTarget() {
        assertThrows(IllegalArgumentException.class, () -> {
            finder.findShortestPath("Pod:default:my-pod", "Pod:default:iso-pod");
        });
    }

    @Test
    void testSourceEqualsTarget() {
        AttackPathResult result = finder.findShortestPath("Pod:default:my-pod", "Pod:default:my-pod");
        assertEquals(1, result.getNodes().size());
        assertEquals(0, result.getTotalCost());
    }

    @Test
    void testInvalidIds() {
        assertThrows(IllegalArgumentException.class, () -> finder.findShortestPath("Invalid", "Pod:default:my-pod"));
        assertThrows(IllegalArgumentException.class, () -> finder.findShortestPath("Pod:default:my-pod", "Invalid"));
    }
}
