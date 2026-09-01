package com.kunal.attackpathvisualizer.core.model;

import com.kunal.attackpathvisualizer.core.enums.ResourceType;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;

public abstract class KubernetesResource {
    private String uid;
    private String name;
    private String namespace;
    private ResourceType type;
    private Map<String, String> labels;
    private Map<String, String> annotations;
    private Instant creationTimestamp;

    protected KubernetesResource(
            String uid,
            String name,
            String namespace,
            ResourceType type,
            Map<String, String> labels,
            Map<String, String> annotations,
            Instant creationTimestamp) {

        this.uid = uid;
        this.name = name;
        this.namespace = namespace;
        this.type = type;
        this.labels = labels != null ? labels : Collections.emptyMap();
        this.annotations = annotations != null ? annotations : Collections.emptyMap();
        this.creationTimestamp = creationTimestamp;
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
        return Collections.unmodifiableMap(labels);
    }

    public Map<String, String> getAnnotations() {
        return Collections.unmodifiableMap(annotations);
    }

    public Instant getCreationTimestamp() {
        return creationTimestamp;
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
