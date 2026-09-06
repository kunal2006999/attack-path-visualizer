package com.kunal.attackpathvisualizer.analysis;

import com.kunal.attackpathvisualizer.graph.GraphNode;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class DijkstraResult {
    private final Map<GraphNode, Integer> distances;
    private final Map<GraphNode, GraphNode> previous;

    public DijkstraResult(
            Map<GraphNode, Integer> distances,
            Map<GraphNode, GraphNode> previous) {

        this.distances =
                Collections.unmodifiableMap(new HashMap<>(distances));
        this.previous = previous;
    }

    public Map<GraphNode, Integer> getDistances() {
        return distances;
    }

    public Map<GraphNode, GraphNode> getPrevious() {
        return previous;
    }
}
