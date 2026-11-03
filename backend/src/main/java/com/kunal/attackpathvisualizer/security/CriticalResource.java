package com.kunal.attackpathvisualizer.security;

import com.kunal.attackpathvisualizer.graph.GraphNode;

import java.util.Objects;

public record CriticalResource(
        GraphNode resource,
        int riskScore,
        int affectedSecretCount,
        int findingCount,
        String reason
) {

    public CriticalResource {
        Objects.requireNonNull(
                resource,
                "Resource cannot be null"
        );

        if (riskScore < 0 || riskScore > 100) {
            throw new IllegalArgumentException(
                    "Risk score must be between 0 and 100"
            );
        }

        if (affectedSecretCount < 0) {
            throw new IllegalArgumentException(
                    "Affected Secret count cannot be negative"
            );
        }

        if (findingCount < 0) {
            throw new IllegalArgumentException(
                    "Finding count cannot be negative"
            );
        }

        if (reason == null || reason.isBlank()) {
            throw new IllegalArgumentException(
                    "Reason cannot be blank"
            );
        }
    }
}