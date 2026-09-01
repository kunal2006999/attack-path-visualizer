package com.kunal.attackpathvisualizer.core.model;

import com.kunal.attackpathvisualizer.core.enums.ResourceType;

import java.time.Instant;
import java.util.Map;

public class Node extends KubernetesResource{
    public Node(
            String uid,
            String name,
            Map<String, String> labels,
            Map<String, String> annotations, Instant creationTimestamp) {

        super(
                uid,
                name,
                null,
                ResourceType.NODE,
                labels,
                annotations,
                creationTimestamp
        );
    }
}
