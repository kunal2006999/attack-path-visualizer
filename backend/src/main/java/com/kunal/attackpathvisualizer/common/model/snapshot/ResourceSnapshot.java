package com.kunal.attackpathvisualizer.common.model.snapshot;

import java.time.Instant;
import java.util.Map;

/**
 * Abstract base DTO for all Kubernetes resource snapshots.
 */
public abstract class ResourceSnapshot {

    private String uid;
    private String name;
    private String namespace;
    private Map<String, String> labels;
    private Map<String, String> annotations;
    private Instant creationTimestamp;

    public ResourceSnapshot() {}

    public String getUid() { return uid; }
    public void setUid(String uid) { this.uid = uid; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getNamespace() { return namespace; }
    public void setNamespace(String namespace) { this.namespace = namespace; }

    public Map<String, String> getLabels() { return labels; }
    public void setLabels(Map<String, String> labels) { this.labels = labels; }

    public Map<String, String> getAnnotations() { return annotations; }
    public void setAnnotations(Map<String, String> annotations) { this.annotations = annotations; }

    public Instant getCreationTimestamp() { return creationTimestamp; }
    public void setCreationTimestamp(Instant creationTimestamp) { this.creationTimestamp = creationTimestamp; }
}
