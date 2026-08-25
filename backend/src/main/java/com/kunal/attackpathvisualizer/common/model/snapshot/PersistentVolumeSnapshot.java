package com.kunal.attackpathvisualizer.common.model.snapshot;

/** Snapshot DTO for a Kubernetes PersistentVolume (cluster-scoped). Maps to core.model.PersistentVolume. */
public class PersistentVolumeSnapshot extends ResourceSnapshot {

    private String storageClassName;

    public PersistentVolumeSnapshot() {}

    public String getStorageClassName() { return storageClassName; }
    public void setStorageClassName(String storageClassName) { this.storageClassName = storageClassName; }
}
