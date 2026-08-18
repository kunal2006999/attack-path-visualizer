package com.kunal.attackpathvisualizer.core.builder;

import com.kunal.attackpathvisualizer.core.model.*;
import com.kunal.attackpathvisualizer.core.relation.RelationshipType;
import com.kunal.attackpathvisualizer.core.relation.ResourceRelationship;

import java.util.List;
import java.util.Map;

public class MockClusterBuilder {
    public static Cluster build() {

        Cluster cluster = new Cluster("mock-cluster");

        // -------------------------
        // Namespace
        // -------------------------

        Namespace production = new Namespace(
                "ns-001",
                "production",
                Map.of("environment", "production"),
                Map.of()
        );

        // -------------------------
        // ServiceAccount
        // -------------------------

        ServiceAccount backendSa = new ServiceAccount(
                "sa-001",
                "backend-sa",
                "production",
                Map.of("app", "backend"),
                Map.of()
        );

        // -------------------------
        // Pod
        // -------------------------

        Pod backendPod = new Pod(
                "pod-001",
                "backend-pod",
                "production",
                Map.of("app", "backend"),
                Map.of(),
                "backend-sa"
        );

        // -------------------------
        // Service
        // -------------------------

        Service backendService = new Service(
                "svc-001",
                "backend-service",
                "production",
                Map.of("app", "backend"),
                Map.of(),
                Map.of("app", "backend")
        );

        // -------------------------
        // Deployment
        // -------------------------

        Deployment backendDeployment = new Deployment(
                "deploy-001",
                "backend",
                "production",
                Map.of("app", "backend"),
                Map.of(),
                2,
                Map.of("app", "backend")
        );

        // -------------------------
        // Secret
        // -------------------------

        Secret databaseSecret = new Secret(
                "secret-001",
                "database-secret",
                "production",
                Map.of("type", "database"),
                Map.of(),
                "Opaque"
        );

        // -------------------------
        // RBAC Rule
        // -------------------------

        RbacRule secretReadRule = new RbacRule(
                List.of(""),
                List.of("secrets"),
                List.of("get", "list"),
                List.of()
        );

        // -------------------------
        // Role
        // -------------------------

        Role backendRole = new Role(
                "role-001",
                "backend-reader",
                "production",
                Map.of(),
                Map.of(),
                List.of(secretReadRule)
        );

        // -------------------------
        // RoleBinding
        // -------------------------

        RoleBinding backendBinding = new RoleBinding(
                "binding-001",
                "backend-binding",
                "production",
                Map.of(),
                Map.of(),
                "backend-sa",
                "backend-reader"
        );

        // -------------------------
        // Add resources to cluster
        // -------------------------

        cluster.addResource(production);
        cluster.addResource(backendSa);
        cluster.addResource(backendPod);
        cluster.addResource(backendService);
        cluster.addResource(backendDeployment);
        cluster.addResource(databaseSecret);
        cluster.addResource(backendRole);
        cluster.addResource(backendBinding);

        // -------------------------
        // Add relationships
        // -------------------------

        cluster.addRelationship(
                new ResourceRelationship(
                        backendPod,
                        backendSa,
                        RelationshipType.USES
                )
        );

        cluster.addRelationship(
                new ResourceRelationship(
                        backendBinding,
                        backendRole,
                        RelationshipType.BINDS
                )
        );

        cluster.addRelationship(
                new ResourceRelationship(
                        backendService,
                        backendPod,
                        RelationshipType.SELECTS
                )
        );

        cluster.addRelationship(
                new ResourceRelationship(
                        backendPod,
                        databaseSecret,
                        RelationshipType.MOUNTS
                )
        );

        return cluster;
    }
}
