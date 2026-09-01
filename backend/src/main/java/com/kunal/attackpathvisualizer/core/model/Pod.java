package com.kunal.attackpathvisualizer.core.model;

import com.kunal.attackpathvisualizer.core.enums.ResourceType;

import java.time.Instant;
import java.util.Map;

public class Pod extends KubernetesResource{
    private String serviceAccountName;

    public Pod(
            String uid,
            String name,
            String namespace,
            Map<String, String> labels,
            Map<String, String> annotations,
            Instant creationTimestamp, String serviceAccountName) {

        super(
                uid,
                name,
                namespace,
                ResourceType.POD,
                labels,
                annotations,
                creationTimestamp
        );

        this.serviceAccountName = serviceAccountName;
    }

    public String getServiceAccountName() {
        return serviceAccountName;
    }
}
