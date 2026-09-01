package com.kunal.attackpathvisualizer.core.model;

import com.kunal.attackpathvisualizer.core.enums.ResourceType;

import java.time.Instant;
import java.util.Map;

public class RoleBinding extends KubernetesResource{
    private java.util.List<String> subjectNames;
    private String roleName;

    public RoleBinding(
            String uid,
            String name,
            String namespace,
            Map<String, String> labels,
            Map<String, String> annotations,
            Instant creationTimestamp, java.util.List<String> subjectNames,
            String roleName) {

        super(
                uid,
                name,
                namespace,
                ResourceType.ROLE_BINDING,
                labels,
                annotations,
                creationTimestamp
        );

        this.subjectNames = subjectNames;
        this.roleName = roleName;
    }

    public java.util.List<String> getSubjectNames() {
        return subjectNames;
    }

    public String getRoleName() {
        return roleName;
    }
}
