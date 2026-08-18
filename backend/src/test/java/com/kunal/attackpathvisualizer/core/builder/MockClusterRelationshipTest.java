package com.kunal.attackpathvisualizer.core.builder;

import com.kunal.attackpathvisualizer.core.model.Cluster;
import com.kunal.attackpathvisualizer.core.relation.RelationshipType;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class MockClusterRelationshipTest {
    @Test
    void shouldBuildExpectedRelationships() {

        Cluster cluster = MockClusterBuilder.build();

        assertTrue(hasRelationship(
                cluster,
                "backend-pod",
                "backend-sa",
                RelationshipType.USES
        ));

        assertTrue(hasRelationship(
                cluster,
                "backend-binding",
                "backend-reader",
                RelationshipType.BINDS
        ));

        assertTrue(hasRelationship(
                cluster,
                "backend-service",
                "backend-pod",
                RelationshipType.SELECTS
        ));

        assertTrue(hasRelationship(
                cluster,
                "backend-pod",
                "database-secret",
                RelationshipType.MOUNTS
        ));
    }

    private boolean hasRelationship(
            Cluster cluster,
            String sourceName,
            String targetName,
            RelationshipType relationshipType) {

        return cluster.getRelationships()
                .stream()
                .anyMatch(relationship ->
                        relationship.getSource().getName().equals(sourceName)
                                && relationship.getTarget().getName().equals(targetName)
                                && relationship.getType() == relationshipType
                );
    }
}
