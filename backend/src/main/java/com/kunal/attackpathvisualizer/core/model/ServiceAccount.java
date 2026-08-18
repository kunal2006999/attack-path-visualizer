package com.kunal.attackpathvisualizer.core.model;

import com.kunal.attackpathvisualizer.core.enums.ResourceType;

import java.util.Map;

public class ServiceAccount extends KubernetesResource{
    public ServiceAccount(
            String uid,
            String name,
            String namespace,
            Map<String, String> labels,
            Map<String, String> annotations) {

        super(
                uid,
                name,
                namespace,
                ResourceType.SERVICE_ACCOUNT,
                labels,
                annotations
        );
    }
}
