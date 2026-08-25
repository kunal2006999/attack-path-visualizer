package com.kunal.attackpathvisualizer.common.model.snapshot;

import java.util.List;

/**
 * Snapshot DTO for a single RBAC policy rule entry.
 * Does NOT extend ResourceSnapshot - it is a nested object in a Role/ClusterRole.
 * Maps to core.model.RbacRule.
 */
public class RbacRuleSnapshot {

    private List<String> apiGroups;
    private List<String> resources;
    private List<String> verbs;
    private List<String> resourceNames;

    public RbacRuleSnapshot() {}

    public List<String> getApiGroups() { return apiGroups; }
    public void setApiGroups(List<String> apiGroups) { this.apiGroups = apiGroups; }

    public List<String> getResources() { return resources; }
    public void setResources(List<String> resources) { this.resources = resources; }

    public List<String> getVerbs() { return verbs; }
    public void setVerbs(List<String> verbs) { this.verbs = verbs; }

    public List<String> getResourceNames() { return resourceNames; }
    public void setResourceNames(List<String> resourceNames) { this.resourceNames = resourceNames; }
}
