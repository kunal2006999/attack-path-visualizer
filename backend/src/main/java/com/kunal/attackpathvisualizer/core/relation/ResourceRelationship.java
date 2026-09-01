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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ResourceRelationship that = (ResourceRelationship) o;
        return java.util.Objects.equals(source, that.source) &&
                java.util.Objects.equals(target, that.target) &&
                type == that.type;
    }

    @Override
    public int hashCode() {
        return java.util.Objects.hash(source, target, type);
    }
}
