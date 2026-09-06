package com.kunal.attackpathvisualizer.analysis;

import com.kunal.attackpathvisualizer.graph.AttackGraph;
import com.kunal.attackpathvisualizer.graph.GraphEdge;
import com.kunal.attackpathvisualizer.graph.GraphNode;

import java.util.*;

public class DijkstraAnalyzer {

    private final AttackGraph graph;

    public DijkstraAnalyzer(AttackGraph graph) {
        this.graph = graph;
    }

    public DijkstraResult shortestDistances(String sourceId) {
        Map<GraphNode, Integer> distances = new HashMap<>();
        Map<GraphNode, GraphNode> previous = new HashMap<>();
        PriorityQueue<QueueEntry> pqueue= new PriorityQueue<>();
        GraphNode source = graph.getNode(sourceId);
        if (source == null) {
            throw new IllegalArgumentException("Node not found: " + sourceId);
        }
        pqueue.add(new QueueEntry(source, 0));
        distances.put(source, 0);

        while(!pqueue.isEmpty()) {
            QueueEntry entry = pqueue.remove();
            GraphNode currNode = entry.node;
            int distance = entry.distance;
            if(distances.get(currNode) < distance) continue;
            for(GraphEdge edge: graph.getOutgoingEdges(currNode.getId())) {
                GraphNode target = edge.getTarget();
                int weight = edge.getWeight();
                int newDistance = distance + weight;
                if (newDistance < distances.getOrDefault(target, Integer.MAX_VALUE)) {
                    previous.put(target, currNode);
                    distances.put(target, newDistance);
                    pqueue.add(new QueueEntry(target, newDistance));
                }
            }
        }

        DijkstraResult dijkstraResult = new DijkstraResult(distances, previous);
        return dijkstraResult;
    }

    public class QueueEntry implements Comparable<QueueEntry>{
        GraphNode node;
        int distance;

        QueueEntry(GraphNode node, int distance) {
            this.node = node;
            this.distance = distance;
        }

        @Override
        public int compareTo(QueueEntry other) {
            return Integer.compare(this.distance, other.distance);
        }
    }
}


