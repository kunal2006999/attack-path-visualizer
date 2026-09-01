package com.kunal.attackpathvisualizer.graph;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.core.JacksonException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@org.springframework.stereotype.Component
public class GraphJsonExporter {
    private final ObjectMapper objectMapper;

    public GraphJsonExporter() {
        this.objectMapper = new ObjectMapper();
    }

    public String export(AttackGraph graph) {

        Map<String, Object> result = new HashMap<>();

        List<Map<String, Object>> nodes = new ArrayList<>();

        for (GraphNode node : graph.getNodes()) {

            Map<String, Object> nodeData = new HashMap<>();

            nodeData.put("id", node.getId());
            nodeData.put("resourceId", node.getResourceId());
            nodeData.put("type", node.getResourceType());
            nodeData.put("name", node.getName());
            nodeData.put("namespace", node.getNamespace());

            nodes.add(nodeData);
        }

        List<Map<String, Object>> edges = new ArrayList<>();

        for (GraphNode node : graph.getNodes()) {

            for (GraphEdge edge : graph.getOutgoingEdges(node.getId())) {

                Map<String, Object> edgeData = new HashMap<>();

                edgeData.put("source", edge.getSource().getId());
                edgeData.put("target", edge.getTarget().getId());
                edgeData.put("type", edge.getRelationshipType());

                edges.add(edgeData);
            }
        }

        result.put("nodes", nodes);
        result.put("edges", edges);

        try {
            return objectMapper.writeValueAsString(result);
        } catch (JacksonException e) {
            throw new IllegalStateException("Failed to export graph as JSON", e);
        }
    }
}
