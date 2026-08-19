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
}
