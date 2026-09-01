package com.kunal.attackpathvisualizer.core.model;

import com.kunal.attackpathvisualizer.core.enums.ResourceType;

import java.time.Instant;
import java.util.Map;

public class ClusterRoleBinding extends KubernetesResource{
    private java.util.List<String> subjectNames;
    private String clusterRoleName;

    public ClusterRoleBinding(
            String uid,
            String name,
            Map<String, String> labels,
            Map<String, String> annotations,
            Instant creationTimestamp, java.util.List<String> subjectNames,
            String clusterRoleName) {

        super(
                uid,
                name,
                null,
                ResourceType.CLUSTER_ROLE_BINDING,
                labels,
                annotations,
                creationTimestamp
        );

        this.subjectNames = subjectNames;
        this.clusterRoleName = clusterRoleName;
    }

    public java.util.List<String> getSubjectNames() {
        return subjectNames;
    }

    public String getClusterRoleName() {
        return clusterRoleName;
    }
}
