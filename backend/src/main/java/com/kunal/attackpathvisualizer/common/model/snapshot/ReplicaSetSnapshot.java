package com.kunal.attackpathvisualizer.common.model.snapshot;

import java.util.Map;

/** Snapshot DTO for a Kubernetes ReplicaSet. Maps to core.model.ReplicaSet. */
public class ReplicaSetSnapshot extends ResourceSnapshot {

    private int replicas;
    private Map<String, String> selector;

    public ReplicaSetSnapshot() {}

    public int getReplicas() { return replicas; }
    public void setReplicas(int replicas) { this.replicas = replicas; }

    public Map<String, String> getSelector() { return selector; }
    public void setSelector(Map<String, String> selector) { this.selector = selector; }
}
