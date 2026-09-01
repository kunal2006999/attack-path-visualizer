package com.kunal.attackpathvisualizer.core.model;

import com.kunal.attackpathvisualizer.core.relation.ResourceRelationship;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.ArrayList;

public class Cluster {
    private String name;

    private Map<String, KubernetesResource> resources;
    private Set<ResourceRelationship> relationships;

    public Cluster(String name) {
        this.name = name;
        this.resources = new LinkedHashMap<>();
        this.relationships = new LinkedHashSet<>();
    }

    public String getName() {
        return name;
    }

    public List<KubernetesResource> getResources() {
        return List.copyOf(resources.values());
    }

    public List<ResourceRelationship> getRelationships() {
        return List.copyOf(relationships);
    }

    public void addResource(KubernetesResource resource) {
        if (resource != null && resource.getUid() != null) {
            resources.putIfAbsent(resource.getUid(), resource);
        }
    }

    public void addRelationship(ResourceRelationship relationship) {
        if (relationship != null) {
            relationships.add(relationship);
        }
    }
}
