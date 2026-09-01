package com.kunal.attackpathvisualizer.core.builder;

import com.kunal.attackpathvisualizer.core.model.Cluster;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class MockClusterBuilderTest {
    @Test
    void shouldBuildMockCluster() {
        Cluster cluster = MockClusterBuilder.build();

        assertNotNull(cluster);

        assertEquals("mock-cluster", cluster.getName());

        assertFalse(cluster.getResources().isEmpty());
        assertFalse(cluster.getRelationships().isEmpty());

        assertEquals(8, cluster.getResources().size());
        assertEquals(5, cluster.getRelationships().size());
    }
}
