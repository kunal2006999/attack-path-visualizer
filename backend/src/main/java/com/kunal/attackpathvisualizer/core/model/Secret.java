package com.kunal.attackpathvisualizer.core.model;

import com.kunal.attackpathvisualizer.core.enums.ResourceType;

import java.util.Map;

public class Secret extends KubernetesResource{
    private String secretType;

    public Secret(
            String uid,
            String name,
            String namespace,
            Map<String, String> labels,
            Map<String, String> annotations,
            String secretType) {

        super(
                uid,
                name,
                namespace,
                ResourceType.SECRET,
                labels,
                annotations
        );

        this.secretType = secretType;
    }

    public String getSecretType() {
        return secretType;
    }
}
