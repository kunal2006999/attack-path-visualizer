package com.kunal.attackpathvisualizer.analysis;

import com.kunal.attackpathvisualizer.graph.AttackGraph;
import com.kunal.attackpathvisualizer.graph.GraphNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class BlastRadiusAnalyzerTest {

    private AttackGraph graph;
    private BlastRadiusAnalyzer analyzer;

    @BeforeEach
    void setUp() {
        graph = GraphTestFixtures.createTestGraph();
        analyzer = new BlastRadiusAnalyzer(graph);
    }

    @Test
    void testBlastRadiusNormal() {
        BlastRadiusResult result = analyzer.BlastRadius("Pod:default:my-pod");
        assertEquals("Pod:default:my-pod", result.getSource().getId());
        List<GraphNode> affected = result.getAffectedNodes();
        
        assertFalse(affected.contains(graph.getNode("Pod:default:my-pod")), "Source itself should not be in affected nodes");
        assertTrue(affected.contains(graph.getNode("ServiceAccount:default:my-sa")));
        assertTrue(affected.contains(graph.getNode("RoleBinding:default:my-rb")));
        assertTrue(affected.contains(graph.getNode("Role:default:my-role")));
        assertTrue(affected.contains(graph.getNode("Secret:default:my-secret")));
    }

    @Test
    void testBlastRadiusDisconnected() {
        BlastRadiusResult result = analyzer.BlastRadius("Pod:default:iso-pod");
        List<GraphNode> affected = result.getAffectedNodes();
        
        assertEquals(1, affected.size());
        assertTrue(affected.contains(graph.getNode("ServiceAccount:default:iso-sa")));
        assertFalse(affected.contains(graph.getNode("Pod:default:my-pod")));
    }

    @Test
    void testInvalidSourceId() {
        assertThrows(IllegalArgumentException.class, () -> analyzer.BlastRadius("NonExistent"));
    }
}
