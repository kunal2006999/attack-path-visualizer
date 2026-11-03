package com.kunal.attackpathvisualizer.security;

import com.kunal.attackpathvisualizer.graph.GraphNode;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

public record Finding(
        String id,
        String title,
        String description,
        GraphNode entryPoint,
        GraphNode target,
        List<GraphNode> attackPath,
        int riskScore,
        Severity severity,
        List<ScoreFactor> scoreFactors,
        String recommendation
) {

    public Finding {
        if (id == null || id.isBlank()) {
            id = UUID.randomUUID().toString();
        }

        if (title == null || title.isBlank()) {
            throw new IllegalArgumentException(
                    "Finding title cannot be blank"
            );
        }

        if (description == null || description.isBlank()) {
            throw new IllegalArgumentException(
                    "Finding description cannot be blank"
            );
        }

        Objects.requireNonNull(entryPoint, "Entry point cannot be null");
        Objects.requireNonNull(target, "Target cannot be null");
        Objects.requireNonNull(severity, "Severity cannot be null");

        if (riskScore < 0 || riskScore > 100) {
            throw new IllegalArgumentException(
                    "Risk score must be between 0 and 100"
            );
        }

        if (severity != Severity.of(riskScore)) {
            throw new IllegalArgumentException(
                    "Severity does not match the risk score"
            );
        }

        if (recommendation == null || recommendation.isBlank()) {
            throw new IllegalArgumentException(
                    "Recommendation cannot be blank"
            );
        }

        attackPath = List.copyOf(
                Objects.requireNonNull(
                        attackPath,
                        "Attack path cannot be null"
                )
        );

        scoreFactors = List.copyOf(
                Objects.requireNonNull(
                        scoreFactors,
                        "Score factors cannot be null"
                )
        );
    }
}