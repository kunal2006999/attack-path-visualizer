package com.kunal.attackpathvisualizer.core.model;

import com.kunal.attackpathvisualizer.core.enums.ResourceType;

import java.time.Instant;
import java.util.Map;

public class Service extends KubernetesResource{
    private Map<String, String> selector;

    public Service(
            String uid,
            String name,
            String namespace,
            Map<String, String> labels,
            Map<String, String> annotations,
            Instant creationTimestamp, Map<String, String> selector) {

        super(
                uid,
                name,
                namespace,
                ResourceType.SERVICE,
                labels,
                annotations,
                creationTimestamp
        );

        this.selector = selector;
    }

    public Map<String, String> getSelector() {
        return selector;
    }
}
