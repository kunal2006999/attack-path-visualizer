package com.kunal.attackpathvisualizer.core.model;

import com.kunal.attackpathvisualizer.core.enums.ResourceType;

import java.util.Map;

public class RoleBinding extends KubernetesResource{
    private String subjectName;
    private String roleName;

    public RoleBinding(
            String uid,
            String name,
            String namespace,
            Map<String, String> labels,
            Map<String, String> annotations,
            String subjectName,
            String roleName) {

        super(
                uid,
                name,
                namespace,
                ResourceType.ROLE_BINDING,
                labels,
                annotations
        );

        this.subjectName = subjectName;
        this.roleName = roleName;
    }

    public String getSubjectName() {
        return subjectName;
    }

    public String getRoleName() {
        return roleName;
    }
}
