package com.kunal.attackpathvisualizer.analysis;

import com.kunal.attackpathvisualizer.graph.AttackGraph;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class ReachabilityAnalyzerTest {

    private AttackGraph graph;
    private ReachabilityAnalyzer analyzer;

    @BeforeEach
    void setUp() {
        graph = GraphTestFixtures.createTestGraph();
        analyzer = new ReachabilityAnalyzer(graph);
    }

    @Test
    void testDirectlyReachable() {
        assertTrue(analyzer.isReachable("Pod:default:my-pod", "ServiceAccount:default:my-sa"));
    }

    @Test
    void testMultiHopReachable() {
        assertTrue(analyzer.isReachable("Pod:default:my-pod", "Secret:default:my-secret"));
    }

    @Test
    void testUnreachable() {
        assertFalse(analyzer.isReachable("Pod:default:my-pod", "Pod:default:iso-pod"));
    }

    @Test
    void testReverseDirection() {
        assertFalse(analyzer.isReachable("Secret:default:my-secret", "Pod:default:my-pod"), "Should be directed graph");
    }

    @Test
    void testSourceEqualsTarget() {
        assertTrue(analyzer.isReachable("Pod:default:my-pod", "Pod:default:my-pod"));
    }

    @Test
    void testInvalidIds() {
        assertThrows(IllegalArgumentException.class, () -> analyzer.isReachable("Invalid", "Pod:default:my-pod"));
        assertThrows(IllegalArgumentException.class, () -> analyzer.isReachable("Pod:default:my-pod", "Invalid"));
    }
}
