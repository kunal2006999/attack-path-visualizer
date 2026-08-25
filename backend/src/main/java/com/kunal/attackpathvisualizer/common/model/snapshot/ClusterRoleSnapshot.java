package com.kunal.attackpathvisualizer.common.model.snapshot;

import java.util.List;

/** Snapshot DTO for a Kubernetes ClusterRole (cluster-scoped). Maps to core.model.ClusterRole. */
public class ClusterRoleSnapshot extends ResourceSnapshot {

    private List<RbacRuleSnapshot> rules;

    public ClusterRoleSnapshot() {}

    public List<RbacRuleSnapshot> getRules() { return rules; }
    public void setRules(List<RbacRuleSnapshot> rules) { this.rules = rules; }
}
