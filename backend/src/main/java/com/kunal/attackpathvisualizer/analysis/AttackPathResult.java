package com.kunal.attackpathvisualizer.analysis;

import com.kunal.attackpathvisualizer.graph.GraphNode;

import java.util.List;

public class AttackPathResult {

    private final GraphNode source;
    private final GraphNode target;
    private final List<GraphNode> nodes;
    private final int totalCost;

    public AttackPathResult(GraphNode source, GraphNode target, List<GraphNode> nodes, int totalCost) {
        this.source = source;
        this.target = target;
        this.nodes = nodes;
        this.totalCost = totalCost;
    }

    public GraphNode getSource() {
        return source;
    }

    public GraphNode getTarget() {
        return target;
    }

    public List<GraphNode> getNodes() {
        return nodes;
    }

    public int getTotalCost() {
        return totalCost;
    }
}
