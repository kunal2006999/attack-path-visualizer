package com.kunal.attackpathvisualizer.common.model.snapshot;

import java.util.List;

/** Snapshot DTO for a Kubernetes Role (namespace-scoped). Maps to core.model.Role. */
public class RoleSnapshot extends ResourceSnapshot {

    private List<RbacRuleSnapshot> rules;

    public RoleSnapshot() {}

    public List<RbacRuleSnapshot> getRules() { return rules; }
    public void setRules(List<RbacRuleSnapshot> rules) { this.rules = rules; }
}
