package com.kunal.attackpathvisualizer.graph;

import com.kunal.attackpathvisualizer.core.enums.ResourceType;

public class GraphNode {
    private String id;
    private String resourceId;
    private ResourceType resourceType;
    private String name;
    private String namespace;

    public GraphNode(
            String id,
            String resourceId,
            ResourceType resourceType,
            String name,
            String namespace) {

        this.id = id;
        this.resourceId = resourceId;
        this.resourceType = resourceType;
        this.name = name;
        this.namespace = namespace;
    }

    public String getId() {
        return id;
    }

    public String getResourceId() {
        return resourceId;
    }

    public ResourceType getResourceType() {
        return resourceType;
    }

    public String getName() {
        return name;
    }

    public String getNamespace() {
        return namespace;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        GraphNode graphNode = (GraphNode) o;
        return java.util.Objects.equals(id, graphNode.id);
    }

    @Override
    public int hashCode() {
        return java.util.Objects.hash(id);
    }
}
