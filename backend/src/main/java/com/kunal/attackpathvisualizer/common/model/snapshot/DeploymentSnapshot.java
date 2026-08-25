package com.kunal.attackpathvisualizer.common.model.snapshot;

import java.util.Map;

/** Snapshot DTO for a Kubernetes Deployment. Maps to core.model.Deployment. */
public class DeploymentSnapshot extends ResourceSnapshot {

    private int replicas;
    private Map<String, String> selector;

    public DeploymentSnapshot() {}

    public int getReplicas() { return replicas; }
    public void setReplicas(int replicas) { this.replicas = replicas; }

    public Map<String, String> getSelector() { return selector; }
    public void setSelector(Map<String, String> selector) { this.selector = selector; }
}
