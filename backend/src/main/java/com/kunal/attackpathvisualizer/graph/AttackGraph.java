package com.kunal.attackpathvisualizer.graph;

import java.util.*;

public class AttackGraph {
    private Map<String, GraphNode> nodes;
    private Map<String, List<GraphEdge>>  adjacencyList;

    public AttackGraph() {
        this.nodes = new HashMap<>();
        this.adjacencyList = new HashMap<>();
    }

    public void addNode(GraphNode node) {
        nodes.putIfAbsent(node.getId(), node);
        adjacencyList.putIfAbsent(node.getId(), new ArrayList<>());
    }

    public GraphNode getNode(String id) {
        return nodes.get(id);
    }

    public void removeNode(String id) {
        nodes.remove(id);
        adjacencyList.remove(id);
        for (List<GraphEdge> edges: adjacencyList.values()) {
            edges.removeIf(edge ->
                    edge.getSource().getId().equals(id)
                            || edge.getTarget().getId().equals(id)
            );
        }
    }

    public void addEdge(GraphEdge edge) {
        String sourceId = edge.getSource().getId();

        addNode(edge.getSource());
        addNode(edge.getTarget());

        List<GraphEdge> edges = adjacencyList.get(sourceId);

        boolean alreadyExists = edges.stream()
                .anyMatch(existingEdge ->
                        existingEdge.getTarget().getId().equals(edge.getTarget().getId())
                                && existingEdge.getRelationshipType() == edge.getRelationshipType()
                );

        if (!alreadyExists) {
            edges.add(edge);
        }
    }

    public List<GraphEdge> getOutgoingEdges(String nodeId) {
        return adjacencyList.getOrDefault(nodeId, Collections.emptyList());
    }

    public List<GraphNode> getNeighbors(String nodeId) {
        List<GraphNode> neighbors = new ArrayList<>();
        for (GraphEdge edge: getOutgoingEdges(nodeId)) {
            neighbors.add(edge.getTarget());
        }
        return neighbors;
    }

    public Collection<GraphNode> getNodes() {
        return Collections.unmodifiableCollection(nodes.values());
    }

    public int getNodeCount() {
        return nodes.size();
    }

    public int getEdgeCount() {
        return adjacencyList.values()
                .stream()
                .mapToInt(List::size)
                .sum();
    }
}
