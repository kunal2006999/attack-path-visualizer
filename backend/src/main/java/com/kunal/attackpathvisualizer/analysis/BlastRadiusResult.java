package com.kunal.attackpathvisualizer.analysis;

import com.kunal.attackpathvisualizer.graph.GraphNode;

import java.util.List;

public class BlastRadiusResult {

    private final List<GraphNode> affectedNodes;
    private final GraphNode source;

    public BlastRadiusResult(List<GraphNode> affectedNodes, GraphNode source) {
        this.source = source;
        this.affectedNodes = affectedNodes;
    }

    public GraphNode getSource() {
        return source;
    }

    public List<GraphNode> getAffectedNodes() {
        return affectedNodes;
    }
}
