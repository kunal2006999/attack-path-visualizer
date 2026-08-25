package com.kunal.attackpathvisualizer.common.model.snapshot;

/** Snapshot DTO for a Kubernetes Pod. Maps to core.model.Pod. */
public class PodSnapshot extends ResourceSnapshot {

    private String serviceAccountName;

    public PodSnapshot() {}

    public String getServiceAccountName() { return serviceAccountName; }
    public void setServiceAccountName(String serviceAccountName) { this.serviceAccountName = serviceAccountName; }
}
