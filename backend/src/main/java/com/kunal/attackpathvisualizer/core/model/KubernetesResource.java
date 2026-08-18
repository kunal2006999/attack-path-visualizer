package com.kunal.attackpathvisualizer.core.model;

import com.kunal.attackpathvisualizer.core.enums.ResourceType;

import java.util.Map;
import java.util.Objects;

public abstract class KubernetesResource {
    private String uid;
    private String name;
    private String namespace;
    private ResourceType type;
    private Map<String, String> labels;
    private Map<String, String> annotations;

    protected KubernetesResource(
            String uid,
            String name,
            String namespace,
            ResourceType type,
            Map<String, String> labels,
            Map<String, String> annotations) {

        this.uid = uid;
        this.name = name;
        this.namespace = namespace;
        this.type = type;
        this.labels = labels;
        this.annotations = annotations;
    }

    public String getUid() {
        return uid;
    }

    public String getName() {
        return name;
    }

    public String getNamespace() {
        return namespace;
    }

    public ResourceType getType() {
        return type;
    }

    public Map<String, String> getLabels() {
        return labels;
    }

    public Map<String, String> getAnnotations() {
        return annotations;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }

        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        KubernetesResource that = (KubernetesResource) o;
        return Objects.equals(uid, that.uid) && type == that.type;
    }

    @Override
    public int hashCode() {
        return Objects.hash(uid, type);
    }

    @Override
    public String toString() {
        return type + "{" +
                "uid='" + uid + '\'' +
                ", name='" + name + '\'' +
                ", namespace='" + namespace + '\'' +
                '}';
    }
}
