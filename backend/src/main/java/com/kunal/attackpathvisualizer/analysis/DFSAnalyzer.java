package com.kunal.attackpathvisualizer.analysis;

import com.kunal.attackpathvisualizer.graph.AttackGraph;
import com.kunal.attackpathvisualizer.graph.GraphNode;

import java.util.*;

public class DFSAnalyzer {

    private final AttackGraph graph;

    public DFSAnalyzer(AttackGraph graph) {
        this.graph = graph;
    }

    public TraversalResult dfs(String sourceId) {
        Deque<GraphNode> stack = new ArrayDeque<>();
        Set<GraphNode> visited = new HashSet<>();
        List<GraphNode> traversalOrder = new ArrayList<>();
        GraphNode source = graph.getNode(sourceId);
        if (source == null) {
            throw new IllegalArgumentException("Node not found: " + sourceId);
        }
        stack.addLast(source);
        visited.add(source);
        traversalOrder.add(source);

        while(!stack.isEmpty()) {
            GraphNode node = stack.removeLast();
            for(GraphNode neighbour: graph.getNeighbors(node.getId())) {
                if(visited.contains(neighbour)) continue;
                visited.add(neighbour);
                traversalOrder.add(neighbour);
                stack.addLast(neighbour);
            }
        }

        TraversalResult traversalResult = new TraversalResult(traversalOrder, source);
        return traversalResult;
    }

}
