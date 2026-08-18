package com.kunal.attackpathvisualizer.core.model;

import com.kunal.attackpathvisualizer.core.relation.ResourceRelationship;

import java.util.ArrayList;
import java.util.List;

public class Cluster {
    private String name;

    private List<KubernetesResource> resources;
    private List<ResourceRelationship> relationships;

    public Cluster(String name) {
        this.name = name;
        this.resources = new ArrayList<>();
        this.relationships = new ArrayList<>();
    }

    public String getName() {
        return name;
    }

    public List<KubernetesResource> getResources() {
        return resources;
    }

    public List<ResourceRelationship> getRelationships() {
        return relationships;
    }

    public void addResource(KubernetesResource resource) {
        resources.add(resource);
    }

    public void addRelationship(ResourceRelationship relationship) {
        relationships.add(relationship);
    }
}
