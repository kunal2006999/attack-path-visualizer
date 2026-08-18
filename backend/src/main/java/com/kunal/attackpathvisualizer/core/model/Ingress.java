package com.kunal.attackpathvisualizer.core.model;

import com.kunal.attackpathvisualizer.core.enums.ResourceType;

import java.util.Map;

public class Ingress extends KubernetesResource{
    private String serviceName;

    public Ingress(
            String uid,
            String name,
            String namespace,
            Map<String, String> labels,
            Map<String, String> annotations,
            String serviceName) {

        super(
                uid,
                name,
                namespace,
                ResourceType.INGRESS,
                labels,
                annotations
        );

        this.serviceName = serviceName;
    }

    public String getServiceName() {
        return serviceName;
    }
}
