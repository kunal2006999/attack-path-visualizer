package com.kunal.attackpathvisualizer.analysis;

import com.kunal.attackpathvisualizer.graph.AttackGraph;
import com.kunal.attackpathvisualizer.graph.GraphNode;

import java.util.*;

public class BFSAnalyzer {
    private final AttackGraph graph;

    public BFSAnalyzer(AttackGraph graph) {
        this.graph = graph;
    }

    public TraversalResult bfs(String sourceId) {
        Queue<GraphNode> queue = new LinkedList<>();
        Set<GraphNode> visited = new HashSet<>();
        List<GraphNode> traversalOrder = new ArrayList<>();
        Map<GraphNode, Integer> distance = new HashMap<>();
        GraphNode source = graph.getNode(sourceId);
        if (source == null) {
            throw new IllegalArgumentException("Node not found: " + sourceId);
        }
        queue.add(source);
        visited.add(source);
        traversalOrder.add(source);
        distance.put(source, 0);


        while(!queue.isEmpty()) {
            GraphNode node = queue.remove();
            for(GraphNode neighbour: graph.getNeighbors(node.getId())) {
                if(visited.contains(neighbour)) continue;
                visited.add(neighbour);
                traversalOrder.add(neighbour);
                distance.put(neighbour, distance.get(node) + 1);
                queue.add(neighbour);
            }
        }

        TraversalResult traversalResult = new TraversalResult(traversalOrder, source);

        return traversalResult;
    }
}
