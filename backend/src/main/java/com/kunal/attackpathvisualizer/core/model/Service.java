package com.kunal.attackpathvisualizer.core.model;

import com.kunal.attackpathvisualizer.core.enums.ResourceType;

import java.util.Map;

public class Service extends KubernetesResource{
    private Map<String, String> selector;

    public Service(
            String uid,
            String name,
            String namespace,
            Map<String, String> labels,
            Map<String, String> annotations,
            Map<String, String> selector) {

        super(
                uid,
                name,
                namespace,
                ResourceType.SERVICE,
                labels,
                annotations
        );

        this.selector = selector;
    }

    public Map<String, String> getSelector() {
        return selector;
    }
}
