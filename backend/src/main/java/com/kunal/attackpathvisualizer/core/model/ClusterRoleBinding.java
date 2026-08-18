package com.kunal.attackpathvisualizer.core.model;

import com.kunal.attackpathvisualizer.core.enums.ResourceType;

import java.util.Map;

public class ClusterRoleBinding extends KubernetesResource{
    private String subjectName;
    private String clusterRoleName;

    public ClusterRoleBinding(
            String uid,
            String name,
            Map<String, String> labels,
            Map<String, String> annotations,
            String subjectName,
            String clusterRoleName) {

        super(
                uid,
                name,
                null,
                ResourceType.CLUSTER_ROLE_BINDING,
                labels,
                annotations
        );

        this.subjectName = subjectName;
        this.clusterRoleName = clusterRoleName;
    }

    public String getSubjectName() {
        return subjectName;
    }

    public String getClusterRoleName() {
        return clusterRoleName;
    }
}
