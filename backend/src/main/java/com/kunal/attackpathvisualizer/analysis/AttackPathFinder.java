package com.kunal.attackpathvisualizer.analysis;

import com.kunal.attackpathvisualizer.graph.AttackGraph;
import com.kunal.attackpathvisualizer.graph.GraphNode;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class AttackPathFinder {

    private final AttackGraph graph;
    private final DijkstraAnalyzer dijkstraAnalyzer;

    public AttackPathFinder(AttackGraph graph) {
        this.graph = graph;
        this.dijkstraAnalyzer = new DijkstraAnalyzer(graph);
    }

    public AttackPathResult findShortestPath(String sourceId, String targetId) {
        GraphNode source = graph.getNode(sourceId);
        GraphNode target = graph.getNode(targetId);
        if (source == null) {
            throw new IllegalArgumentException("Source node not found: " + sourceId);
        }
        if (target == null) {
            throw new IllegalArgumentException("Target node not found: " + targetId);
        }
        DijkstraResult dijkstraResult = dijkstraAnalyzer.shortestDistances(sourceId);
        if (!dijkstraResult.getDistances().containsKey(target)) {
            throw new IllegalArgumentException(
                    "Path not found between " + sourceId + " and " + targetId
            );
        }
        Map<GraphNode, GraphNode> previous = dijkstraResult.getPrevious();
        List<GraphNode> path = new ArrayList<>();
        path.add(target);
        GraphNode current = target;
        while(previous.containsKey(current)) {
            GraphNode prev = previous.get(current);
            path.add(prev);
            current = prev;
        }
        Collections.reverse(path);
        AttackPathResult attackPathResult = new AttackPathResult(source, target, path, dijkstraResult.getDistances().get(target));
        return attackPathResult;
    }
}
