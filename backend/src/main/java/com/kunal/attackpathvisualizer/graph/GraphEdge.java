package com.kunal.attackpathvisualizer.graph;

import com.kunal.attackpathvisualizer.core.relation.RelationshipType;

public class GraphEdge {
    private GraphNode source;
    private GraphNode target;
    private RelationshipType relationshipType;

    public GraphEdge(
            GraphNode source,
            GraphNode target,
            RelationshipType relationshipType) {

        this.source = source;
        this.target = target;
        this.relationshipType = relationshipType;
    }

    public GraphNode getSource() {
        return source;
    }

    public GraphNode getTarget() {
        return target;
    }

    public RelationshipType getRelationshipType() {
        return relationshipType;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        GraphEdge graphEdge = (GraphEdge) o;
        return java.util.Objects.equals(source, graphEdge.source) &&
                java.util.Objects.equals(target, graphEdge.target) &&
                relationshipType == graphEdge.relationshipType;
    }

    @Override
    public int hashCode() {
        return java.util.Objects.hash(source, target, relationshipType);
    }
}
