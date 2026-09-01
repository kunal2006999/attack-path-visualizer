package com.kunal.attackpathvisualizer.core.model;

import com.kunal.attackpathvisualizer.core.enums.ResourceType;

import java.time.Instant;
import java.util.Map;

public class PersistentVolumeClaim extends KubernetesResource{
    private String volumeName;
    private String storageClassName;

    public PersistentVolumeClaim(
            String uid,
            String name,
            String namespace,
            Map<String, String> labels,
            Map<String, String> annotations,
            Instant creationTimestamp, String volumeName,
            String storageClassName) {

        super(
                uid,
                name,
                namespace,
                ResourceType.PERSISTENT_VOLUME_CLAIM,
                labels,
                annotations,
                creationTimestamp
        );

        this.volumeName = volumeName;
        this.storageClassName = storageClassName;
    }

    public String getVolumeName() {
        return volumeName;
    }

    public String getStorageClassName() {
        return storageClassName;
    }
}
