package com.kunal.attackpathvisualizer.core.model;

import com.kunal.attackpathvisualizer.core.enums.ResourceType;

import java.time.Instant;
import java.util.Map;

public class ReplicaSet extends KubernetesResource{

    private int replicas;
    private Map<String, String> selector;

    public ReplicaSet(
            String uid,
            String name,
            String namespace,
            Map<String, String> labels,
            Map<String, String> annotations,
            Instant creationTimestamp, int replicas,
            Map<String, String> selector) {

        super(
                uid,
                name,
                namespace,
                ResourceType.REPLICASET,
                labels,
                annotations,
                creationTimestamp
        );

        this.replicas = replicas;
        this.selector = selector;
    }

    public int getReplicas() {
        return replicas;
    }

    public Map<String, String> getSelector() {
        return selector;
    }
}
