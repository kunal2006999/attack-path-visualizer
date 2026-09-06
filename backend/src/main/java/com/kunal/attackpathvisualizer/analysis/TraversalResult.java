package com.kunal.attackpathvisualizer.analysis;

import com.kunal.attackpathvisualizer.graph.GraphNode;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class TraversalResult {

    private final List<GraphNode> traversalOrder;
    private final GraphNode source;

    public TraversalResult(List<GraphNode> traversalOrder, GraphNode source) {
        this.traversalOrder =
                Collections.unmodifiableList(new ArrayList<>(traversalOrder));
        this.source = source;
    }

    public List<GraphNode> getTraversalOrder() {
        return traversalOrder;
    }

    public GraphNode getSource() {
        return source;
    }
}
