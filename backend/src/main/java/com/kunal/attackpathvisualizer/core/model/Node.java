package com.kunal.attackpathvisualizer.core.model;

import com.kunal.attackpathvisualizer.core.enums.ResourceType;

import java.util.Map;

public class Node extends KubernetesResource{
    private String nodeName;

    public Node(
            String uid,
            String name,
            Map<String, String> labels,
            Map<String, String> annotations) {

        super(
                uid,
                name,
                null,
                ResourceType.NODE,
                labels,
                annotations
        );

        this.nodeName = name;
    }

    public String getNodeName() {
        return nodeName;
    }
}
