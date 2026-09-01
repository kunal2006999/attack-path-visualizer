package com.kunal.attackpathvisualizer.graph;

import com.kunal.attackpathvisualizer.core.model.Cluster;
import com.kunal.attackpathvisualizer.core.model.KubernetesResource;
import com.kunal.attackpathvisualizer.core.relation.ResourceRelationship;

@org.springframework.stereotype.Component
public class GraphBuilder {

    public AttackGraph build(Cluster cluster) {

        AttackGraph graph = new AttackGraph();

        for (KubernetesResource resource: cluster.getResources()) {
            GraphNode node = createNode(resource);
            graph.addNode(node);
        }

        for (ResourceRelationship relationship: cluster.getRelationships()) {
            String sourceId = createNodeId(relationship.getSource());
            String targetId = createNodeId(relationship.getTarget());

            GraphNode source = graph.getNode(sourceId);
            GraphNode target = graph.getNode(targetId);

            if (source == null || target == null) {
                // Skip relationships where nodes do not exist in the graph
                continue;
            }

            GraphEdge edge = new GraphEdge(
                    source,
                    target,
                    relationship.getType()
            );

            graph.addEdge(edge);
        }

        return graph;
    }

    private GraphNode createNode(KubernetesResource resource) {

        String id = createNodeId(resource);

        return new GraphNode(
                id,
                resource.getUid(),
                resource.getType(),
                resource.getName(),
                resource.getNamespace()
        );
    }

    private String createNodeId(KubernetesResource resource) {

        if (resource.getNamespace() == null) {
            return resource.getType() + ":" + resource.getName();
        }

        return resource.getType()
                + ":"
                + resource.getNamespace()
                + ":"
                + resource.getName();
    }
}
