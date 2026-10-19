package com.kunal.attackpathvisualizer.core.model;

import com.kunal.attackpathvisualizer.core.enums.ResourceType;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public class RoleBinding extends KubernetesResource {
    private final List<RbacSubject> subjects;
    private final String roleName;
    private final String roleKind;

    /** Legacy constructor: subject names are treated as ServiceAccounts in the binding's namespace; role kind is Role. */
    public RoleBinding(
            String uid,
            String name,
            String namespace,
            Map<String, String> labels,
            Map<String, String> annotations,
            Instant creationTimestamp,
            List<String> subjectNames,
            String roleName) {
        this(uid, name, namespace, labels, annotations, creationTimestamp,
                roleName, "Role", RbacSubject.fromServiceAccountNames(subjectNames));
    }

    public RoleBinding(
            String uid,
            String name,
            String namespace,
            Map<String, String> labels,
            Map<String, String> annotations,
            Instant creationTimestamp,
            String roleName,
            String roleKind,
            List<RbacSubject> subjects) {

        super(uid, name, namespace, ResourceType.ROLE_BINDING, labels, annotations, creationTimestamp);

        this.roleName = roleName;
        this.roleKind = roleKind == null ? "Role" : roleKind;
        this.subjects = subjects == null ? List.of() : List.copyOf(subjects);
    }

    public List<RbacSubject> getSubjects() {
        return subjects;
    }

    public List<String> getSubjectNames() {
        return subjects.stream().map(RbacSubject::getName).toList();
    }

    public String getRoleName() {
        return roleName;
    }

    public String getRoleKind() {
        return roleKind;
    }
}
