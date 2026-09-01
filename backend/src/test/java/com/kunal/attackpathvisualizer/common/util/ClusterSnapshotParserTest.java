package com.kunal.attackpathvisualizer.common.util;
import com.kunal.attackpathvisualizer.common.model.snapshot.ClusterSnapshot;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class ClusterSnapshotParserTest {
    @Test
    void shouldParseSimpleClusterJson() throws IOException {

        Path file = Path.of(
                "sample-data",
                "clusters",
                "simple-cluster.json"
        );

        ClusterSnapshot snapshot =
                new ClusterSnapshotParser().parse(file);

        assertNotNull(snapshot);

        assertEquals(
                "simple-cluster",
                snapshot.getClusterName()
        );

        assertFalse(snapshot.getNamespaces().isEmpty());
        assertFalse(snapshot.getPods().isEmpty());
        assertFalse(snapshot.getServiceAccounts().isEmpty());
        assertFalse(snapshot.getRoles().isEmpty());
        assertFalse(snapshot.getRoleBindings().isEmpty());
        assertFalse(snapshot.getSecrets().isEmpty());
    }
}
