package com.kunal.attackpathvisualizer.core.model;

import com.kunal.attackpathvisualizer.core.enums.ResourceType;

import java.time.Instant;
import java.util.Map;

public class PersistentVolume extends KubernetesResource{

    private String storageClassName;

    public PersistentVolume(
            String uid,
            String name,
            Map<String, String> labels,
            Map<String, String> annotations,
            Instant creationTimestamp, String storageClassName) {

        super(
                uid,
                name,
                null,
                ResourceType.PERSISTENT_VOLUME,
                labels,
                annotations,
                creationTimestamp
        );

        this.storageClassName = storageClassName;
    }

    public String getStorageClassName() {
        return storageClassName;
    }
}
