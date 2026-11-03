package com.kunal.attackpathvisualizer.security;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public record SecurityReport(
        Instant generatedAt,
        int totalFindings,
        Map<Severity, Integer> severityCounts,
        List<Finding> findings,
        List<CriticalResource> criticalResources
) {

    public SecurityReport {
        generatedAt = Objects.requireNonNull(
                generatedAt,
                "Generated timestamp cannot be null"
        );

        if (totalFindings < 0) {
            throw new IllegalArgumentException(
                    "Total findings cannot be negative"
            );
        }

        severityCounts = Map.copyOf(
                Objects.requireNonNull(
                        severityCounts,
                        "Severity counts cannot be null"
                )
        );

        findings = List.copyOf(
                Objects.requireNonNull(
                        findings,
                        "Findings cannot be null"
                )
        );

        criticalResources = List.copyOf(
                Objects.requireNonNull(
                        criticalResources,
                        "Critical resources cannot be null"
                )
        );

        if (totalFindings != findings.size()) {
            throw new IllegalArgumentException(
                    "Total findings must equal the number of findings"
            );
        }

        int severityTotal = severityCounts.values()
                .stream()
                .mapToInt(Integer::intValue)
                .sum();

        if (severityCounts.values().stream().anyMatch(count -> count < 0)) {
            throw new IllegalArgumentException(
                    "Severity counts cannot be negative"
            );
        }

        if (severityTotal != totalFindings) {
            throw new IllegalArgumentException(
                    "Severity counts must sum to total findings"
            );
        }
    }
}