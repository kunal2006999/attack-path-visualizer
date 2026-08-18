package com.kunal.attackpathvisualizer.core.model;

import java.util.List;

public class RbacRule {
    private List<String> apiGroups;
    private List<String> resources;
    private List<String> verbs;
    private List<String> resourceNames;

    public RbacRule(
            List<String> apiGroups,
            List<String> resources,
            List<String> verbs,
            List<String> resourceNames) {

        this.apiGroups = apiGroups;
        this.resources = resources;
        this.verbs = verbs;
        this.resourceNames = resourceNames;
    }

    public List<String> getApiGroups() {
        return apiGroups;
    }

    public List<String> getResources() {
        return resources;
    }

    public List<String> getVerbs() {
        return verbs;
    }

    public List<String> getResourceNames() {
        return resourceNames;
    }
}

