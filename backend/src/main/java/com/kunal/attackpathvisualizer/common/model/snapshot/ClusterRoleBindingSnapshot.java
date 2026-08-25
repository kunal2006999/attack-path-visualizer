package com.kunal.attackpathvisualizer.common.model.snapshot;

/** Snapshot DTO for a Kubernetes ClusterRoleBinding (cluster-scoped). Maps to core.model.ClusterRoleBinding. */
public class ClusterRoleBindingSnapshot extends ResourceSnapshot {

    private String subjectName;
    private String clusterRoleName;

    public ClusterRoleBindingSnapshot() {}

    public String getSubjectName() { return subjectName; }
    public void setSubjectName(String subjectName) { this.subjectName = subjectName; }

    public String getClusterRoleName() { return clusterRoleName; }
    public void setClusterRoleName(String clusterRoleName) { this.clusterRoleName = clusterRoleName; }
}
