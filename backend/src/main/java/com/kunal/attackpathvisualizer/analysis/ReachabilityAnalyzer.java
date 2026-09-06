package com.kunal.attackpathvisualizer.analysis;

import com.kunal.attackpathvisualizer.graph.AttackGraph;
import com.kunal.attackpathvisualizer.graph.GraphNode;

import java.util.List;

public class ReachabilityAnalyzer {
    private final AttackGraph graph;
    private final BFSAnalyzer bfsAnalyzer;

    public ReachabilityAnalyzer(AttackGraph graph) {
        this.graph = graph;
        this.bfsAnalyzer = new BFSAnalyzer(graph);
    }

    public boolean isReachable(String sourceId, String targetId) {
        List<GraphNode> traversal = bfsAnalyzer.bfs(sourceId).getTraversalOrder();
        GraphNode target = graph.getNode(targetId);
        if (target == null) {
            throw new IllegalArgumentException("Target node not found: " + targetId);
        }
        return traversal.contains(target);
    }
}
