package com.kunal.attackpathvisualizer.core.model;

import com.kunal.attackpathvisualizer.core.enums.ResourceType;

import java.util.Map;

public class Deployment extends KubernetesResource{
    private int replicas;
    private Map<String, String> selector;

    public Deployment(
            String uid,
            String name,
            String namespace,
            Map<String, String> labels,
            Map<String, String> annotations,
            int replicas,
            Map<String, String> selector) {

        super(
                uid,
                name,
                namespace,
                ResourceType.DEPLOYMENT,
                labels,
                annotations
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
