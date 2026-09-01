package com.kunal.attackpathvisualizer.common.model.snapshot;

import java.util.List;

/** Snapshot DTO for a Kubernetes ClusterRoleBinding (cluster-scoped). Maps to core.model.ClusterRoleBinding. */
public class ClusterRoleBindingSnapshot extends ResourceSnapshot {

    private List<String> subjectNames;
    private String clusterRoleName;

    public ClusterRoleBindingSnapshot() {}

    public List<String> getSubjectNames() { return subjectNames; }
    public void setSubjectNames(List<String> subjectNames) { this.subjectNames = subjectNames; }

    public String getClusterRoleName() { return clusterRoleName; }
    public void setClusterRoleName(String clusterRoleName) { this.clusterRoleName = clusterRoleName; }
}
