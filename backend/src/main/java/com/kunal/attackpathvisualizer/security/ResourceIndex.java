package com.kunal.attackpathvisualizer.security;

import com.kunal.attackpathvisualizer.core.model.Cluster;
import com.kunal.attackpathvisualizer.core.model.KubernetesResource;
import com.kunal.attackpathvisualizer.graph.GraphNode;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

public final class ResourceIndex {

    private final Map<String, KubernetesResource> resourcesByUid;

    public ResourceIndex(Cluster cluster) {
        Objects.requireNonNull(
                cluster,
                "Cluster cannot be null"
        );

        Map<String, KubernetesResource> index = new LinkedHashMap<>();

        for (KubernetesResource resource : cluster.getResources()) {
            if (resource == null) {
                continue;
            }

            String uid = resource.getUid();

            if (uid == null || uid.isBlank()) {
                throw new IllegalArgumentException(
                        "Kubernetes resource UID cannot be blank"
                );
            }

            KubernetesResource previous = index.putIfAbsent(
                    uid,
                    resource
            );

            if (previous != null && previous != resource) {
                throw new IllegalArgumentException(
                        "Duplicate Kubernetes resource UID: " + uid
                );
            }
        }

        this.resourcesByUid = Collections.unmodifiableMap(index);
    }

    /**
     * Looks up a Kubernetes resource using its UID.
     */
    public Optional<KubernetesResource> findByUid(String uid) {
        if (uid == null || uid.isBlank()) {
            return Optional.empty();
        }

        return Optional.ofNullable(resourcesByUid.get(uid));
    }

    /**
     * Looks up the original Kubernetes resource represented by a graph node.
     */
    public Optional<KubernetesResource> findByNode(GraphNode node) {
        if (node == null) {
            return Optional.empty();
        }

        return findByUid(node.getResourceId());
    }

    /**
     * Looks up a resource by UID and verifies that it has the requested type.
     */
    public <T extends KubernetesResource> Optional<T> findByUid(
            String uid,
            Class<T> resourceClass
    ) {
        Objects.requireNonNull(
                resourceClass,
                "Resource class cannot be null"
        );

        return findByUid(uid)
                .filter(resourceClass::isInstance)
                .map(resourceClass::cast);
    }

    /**
     * Looks up a resource represented by a graph node
     * and verifies its Java class.
     */
    public <T extends KubernetesResource> Optional<T> findByNode(
            GraphNode node,
            Class<T> resourceClass
    ) {
        Objects.requireNonNull(
                resourceClass,
                "Resource class cannot be null"
        );

        return findByNode(node)
                .filter(resourceClass::isInstance)
                .map(resourceClass::cast);
    }

    /**
     * Returns the number of indexed resources.
     */
    public int size() {
        return resourcesByUid.size();
    }

    /**
     * Returns all indexed resources as a read-only collection.
     */
    public Collection<KubernetesResource> getAllResources() {
        return resourcesByUid.values();
    }
}