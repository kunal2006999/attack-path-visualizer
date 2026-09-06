package com.kunal.attackpathvisualizer.analysis;

import com.kunal.attackpathvisualizer.graph.AttackGraph;
import com.kunal.attackpathvisualizer.graph.GraphNode;

import java.util.ArrayList;
import java.util.List;

public class BlastRadiusAnalyzer {
    private final AttackGraph graph;
    private final BFSAnalyzer bfsAnalyzer;

    public BlastRadiusAnalyzer(AttackGraph graph) {
        this.graph = graph;
        this.bfsAnalyzer = new BFSAnalyzer(graph);
    }

    public BlastRadiusResult BlastRadius(String sourceId) {
        GraphNode source = graph.getNode(sourceId);
        TraversalResult traversalResult =
                bfsAnalyzer.bfs(sourceId);
        List<GraphNode> affectedNodes =
                new ArrayList<>(traversalResult.getTraversalOrder());
        affectedNodes.remove(source);
        return new BlastRadiusResult(affectedNodes, source);
    }
}
