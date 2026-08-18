package com.kunal.attackpathvisualizer.core.relation;

import com.kunal.attackpathvisualizer.core.model.KubernetesResource;

public class ResourceRelationship {
    private KubernetesResource source;
    private KubernetesResource target;
    private RelationshipType type;

    public ResourceRelationship(
            KubernetesResource source,
            KubernetesResource target,
            RelationshipType type) {

        this.source = source;
        this.target = target;
        this.type = type;
    }

    public KubernetesResource getSource() {
        return source;
    }

    public KubernetesResource getTarget() {
        return target;
    }

    public RelationshipType getType() {
        return type;
    }
}
