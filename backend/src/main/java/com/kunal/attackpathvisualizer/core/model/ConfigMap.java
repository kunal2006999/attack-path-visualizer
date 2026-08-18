package com.kunal.attackpathvisualizer.core.model;

import com.kunal.attackpathvisualizer.core.enums.ResourceType;

import java.util.Map;

public class ConfigMap extends KubernetesResource{
    public ConfigMap(
            String uid,
            String name,
            String namespace,
            Map<String, String> labels,
            Map<String, String> annotations) {

        super(
                uid,
                name,
                namespace,
                ResourceType.CONFIG_MAP,
                labels,
                annotations
        );
    }
}
