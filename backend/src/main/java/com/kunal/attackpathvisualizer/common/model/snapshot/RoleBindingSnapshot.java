package com.kunal.attackpathvisualizer.common.model.snapshot;

/** Snapshot DTO for a Kubernetes RoleBinding (namespace-scoped). Maps to core.model.RoleBinding. */
public class RoleBindingSnapshot extends ResourceSnapshot {

    private String subjectName;
    private String roleName;

    public RoleBindingSnapshot() {}

    public String getSubjectName() { return subjectName; }
    public void setSubjectName(String subjectName) { this.subjectName = subjectName; }

    public String getRoleName() { return roleName; }
    public void setRoleName(String roleName) { this.roleName = roleName; }
}
