package com.kunal.attackpathvisualizer.graph;

import com.kunal.attackpathvisualizer.core.model.*;
import com.kunal.attackpathvisualizer.core.relation.RelationshipType;
import com.kunal.attackpathvisualizer.core.relation.ResourceRelationship;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class GraphBuilderEdgeCasesTest {

    private final GraphBuilder builder = new GraphBuilder();

    private static Pod pod(String uid, String name) {
        return new Pod(uid, name, "ns", Map.of(), Map.of(), Instant.EPOCH, "sa");
    }

    private static ServiceAccount sa(String uid, String name) {
        return new ServiceAccount(uid, name, "ns", Map.of(), Map.of(), Instant.EPOCH);
    }

    @Test
    void emptyClusterProducesEmptyGraph() {
        AttackGraph g = builder.build(new Cluster("empty"));
        assertEquals(0, g.getNodeCount());
        assertEquals(0, g.getEdgeCount());
    }

    @Test
    void nullClusterIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> builder.build(null));
    }

    @Test
    void duplicateResourcesDoNotCreateDuplicateNodes() {
        Cluster c = new Cluster("c");
        c.addResource(pod("uid-1", "p"));
        c.addResource(pod("uid-1", "p"));
        assertEquals(1, builder.build(c).getNodeCount());
    }

    @Test
    void edgesPreserveTypeAndDefaultWeightAndEndpointsExist() {
        Cluster c = new Cluster("c");
        Pod p = pod("uid-1", "p");
        ServiceAccount s = sa("uid-2", "sa");
        c.addResource(p);
        c.addResource(s);
        c.addRelationship(new ResourceRelationship(p, s, RelationshipType.USES));

        AttackGraph g = builder.build(c);

        GraphEdge edge = g.getOutgoingEdges("POD:ns:p").get(0);
        assertEquals(RelationshipType.USES, edge.getRelationshipType());
        assertEquals(1, edge.getWeight());
        assertNotNull(g.getNode(edge.getSource().getId()));
        assertNotNull(g.getNode(edge.getTarget().getId()));
    }

    @Test
    void relationshipToResourceNotInClusterIsSkipped() {
        Cluster c = new Cluster("c");
        Pod p = pod("uid-1", "p");
        c.addResource(p);
        c.addRelationship(new ResourceRelationship(p, sa("uid-x", "ghost"), RelationshipType.USES));

        assertEquals(0, builder.build(c).getEdgeCount());
    }

    @Test
    void repeatedConstructionIsConsistent() {
        Cluster c = new Cluster("c");
        Pod p = pod("uid-1", "p");
        ServiceAccount s = sa("uid-2", "sa");
        c.addResource(p);
        c.addResource(s);
        c.addRelationship(new ResourceRelationship(p, s, RelationshipType.USES));

        AttackGraph a = builder.build(c);
        AttackGraph b = builder.build(c);

        assertEquals(a.getNodeCount(), b.getNodeCount());
        assertEquals(a.getEdgeCount(), b.getEdgeCount());
    }
}