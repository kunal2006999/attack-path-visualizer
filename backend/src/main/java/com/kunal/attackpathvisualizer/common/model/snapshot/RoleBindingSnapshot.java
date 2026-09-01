package com.kunal.attackpathvisualizer.common.model.snapshot;

import java.util.List;

/** Snapshot DTO for a Kubernetes RoleBinding (namespace-scoped). Maps to core.model.RoleBinding. */
public class RoleBindingSnapshot extends ResourceSnapshot {

    private List<String> subjectNames;
    private String roleName;

    public RoleBindingSnapshot() {}

    public List<String> getSubjectNames() { return subjectNames; }
    public void setSubjectNames(List<String> subjectNames) { this.subjectNames = subjectNames; }

    public String getRoleName() { return roleName; }
    public void setRoleName(String roleName) { this.roleName = roleName; }
}
