package com.kunal.attackpathvisualizer.common.model.snapshot;

/** Snapshot DTO for a Kubernetes PersistentVolumeClaim. Maps to core.model.PersistentVolumeClaim. */
public class PersistentVolumeClaimSnapshot extends ResourceSnapshot {

    private String volumeName;
    private String storageClassName;

    public PersistentVolumeClaimSnapshot() {}

    public String getVolumeName() { return volumeName; }
    public void setVolumeName(String volumeName) { this.volumeName = volumeName; }

    public String getStorageClassName() { return storageClassName; }
    public void setStorageClassName(String storageClassName) { this.storageClassName = storageClassName; }
}
