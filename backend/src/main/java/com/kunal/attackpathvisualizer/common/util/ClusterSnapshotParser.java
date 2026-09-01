package com.kunal.attackpathvisualizer.common.util;

import com.kunal.attackpathvisualizer.common.model.snapshot.ClusterSnapshot;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Path;

@org.springframework.stereotype.Component
public class ClusterSnapshotParser {
    private final ObjectMapper objectMapper;

    public ClusterSnapshotParser() {
        this.objectMapper = new ObjectMapper();
    }

    public ClusterSnapshot parse(Path filePath) throws IOException {

        return objectMapper.readValue(
                filePath.toFile(),
                ClusterSnapshot.class
        );
    }
}
