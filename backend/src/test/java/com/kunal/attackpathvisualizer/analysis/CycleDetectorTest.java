package com.kunal.attackpathvisualizer.analysis;

import com.kunal.attackpathvisualizer.core.enums.ResourceType;
import com.kunal.attackpathvisualizer.core.relation.RelationshipType;
import com.kunal.attackpathvisualizer.graph.AttackGraph;
import com.kunal.attackpathvisualizer.graph.GraphEdge;
import com.kunal.attackpathvisualizer.graph.GraphNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class CycleDetectorTest {

    private AttackGraph graph;

    @BeforeEach
    void setUp() {
        graph = GraphTestFixtures.createTestGraph();
    }

    @Test
    void testDisconnectedGraphContainingCycle() {
        CycleDetector detector = new CycleDetector(graph);
        assertTrue(detector.hasCycle(), "Graph should contain a cycle");
    }

    @Test
    void testAcyclicGraph() {
        AttackGraph acyclic = new AttackGraph();
        GraphNode n1 = new GraphNode("n1", "1", ResourceType.POD, "n1", "default");
        GraphNode n2 = new GraphNode("n2", "2", ResourceType.POD, "n2", "default");
        GraphNode n3 = new GraphNode("n3", "3", ResourceType.POD, "n3", "default");
        acyclic.addNode(n1);
        acyclic.addNode(n2);
        acyclic.addNode(n3);
        acyclic.addEdge(new GraphEdge(n1, n2, RelationshipType.USES, 1));
        acyclic.addEdge(new GraphEdge(n2, n3, RelationshipType.USES, 1));
        acyclic.addEdge(new GraphEdge(n1, n3, RelationshipType.USES, 1));
        
        CycleDetector detector = new CycleDetector(acyclic);
        assertFalse(detector.hasCycle(), "Graph should be acyclic");
    }

    @Test
    void testSelfLoop() {
        AttackGraph cyclic = new AttackGraph();
        GraphNode n1 = new GraphNode("n1", "1", ResourceType.POD, "n1", "default");
        cyclic.addNode(n1);
        cyclic.addEdge(new GraphEdge(n1, n1, RelationshipType.USES, 1));
        
        CycleDetector detector = new CycleDetector(cyclic);
        assertTrue(detector.hasCycle(), "Graph with self-loop should be cyclic");
    }
    
    @Test
    void testCrossEdgeNotCycle() {
        // Graph where an edge points to an already visited node but NOT an ancestor
        AttackGraph acyclic = new AttackGraph();
        GraphNode root = new GraphNode("root", "1", ResourceType.POD, "root", "default");
        GraphNode left = new GraphNode("left", "2", ResourceType.POD, "left", "default");
        GraphNode right = new GraphNode("right", "3", ResourceType.POD, "right", "default");
        GraphNode bottom = new GraphNode("bottom", "4", ResourceType.POD, "bottom", "default");
        acyclic.addNode(root);
        acyclic.addNode(left);
        acyclic.addNode(right);
        acyclic.addNode(bottom);
        
        acyclic.addEdge(new GraphEdge(root, left, RelationshipType.USES, 1));
        acyclic.addEdge(new GraphEdge(root, right, RelationshipType.USES, 1));
        acyclic.addEdge(new GraphEdge(left, bottom, RelationshipType.USES, 1));
        acyclic.addEdge(new GraphEdge(right, bottom, RelationshipType.USES, 1)); // Cross edge
        
        CycleDetector detector = new CycleDetector(acyclic);
        assertFalse(detector.hasCycle(), "Cross edges should not be detected as cycles");
    }
}
