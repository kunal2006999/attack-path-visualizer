package com.kunal.attackpathvisualizer.core.model;

import com.kunal.attackpathvisualizer.core.enums.ResourceType;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public class ClusterRole extends KubernetesResource {
    private List<RbacRule> rules;

    public ClusterRole(
            String uid,
            String name,
            Map<String, String> labels,
            Map<String, String> annotations,
            Instant creationTimestamp, List<RbacRule> rules) {

        super(
                uid,
                name,
                null,
                ResourceType.CLUSTER_ROLE,
                labels,
                annotations,
                creationTimestamp
        );

        this.rules = rules;
    }

    public List<RbacRule> getRules() {
        return rules;
    }
}
