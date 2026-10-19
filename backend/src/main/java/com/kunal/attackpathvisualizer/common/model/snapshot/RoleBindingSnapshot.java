package com.kunal.attackpathvisualizer.common.model.snapshot;

import java.util.List;

/** Snapshot DTO for a Kubernetes RoleBinding (namespace-scoped). Maps to core.model.RoleBinding. */
public class RoleBindingSnapshot extends ResourceSnapshot {

    private List<String> subjectNames;
    private List<SubjectSnapshot> subjects;
    private String roleName;
    private String roleKind; // "Role" (default when null) or "ClusterRole"

    public RoleBindingSnapshot() {}

    public List<String> getSubjectNames() { return subjectNames; }
    public void setSubjectNames(List<String> subjectNames) { this.subjectNames = subjectNames; }

    public List<SubjectSnapshot> getSubjects() { return subjects; }
    public void setSubjects(List<SubjectSnapshot> subjects) { this.subjects = subjects; }

    public String getRoleName() { return roleName; }
    public void setRoleName(String roleName) { this.roleName = roleName; }

    public String getRoleKind() { return roleKind; }
    public void setRoleKind(String roleKind) { this.roleKind = roleKind; }
}
