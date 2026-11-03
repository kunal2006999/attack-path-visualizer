package com.kunal.attackpathvisualizer.report;

import java.util.List;
import java.util.Map;

/**
 * Stable JSON contract for an exported security report.
 */
public record SecurityReportDto(
        String clusterName,
        String generatedAt,
        int totalFindings,
        Map<String, Integer> severityCounts,
        List<FindingDto> findings,
        List<CriticalResourceDto> criticalResources
) {

    public record NodeDto(
            String id,
            String resourceId,
            String type,
            String name,
            String namespace
    ) {
    }

    public record ScoreFactorDto(
            String name,
            int points,
            String reason
    ) {
    }

    public record FindingDto(
            String id,
            String title,
            String description,
            NodeDto entryPoint,
            NodeDto target,
            List<NodeDto> attackPath,
            int riskScore,
            String severity,
            List<ScoreFactorDto> scoreFactors,
            String recommendation
    ) {
    }

    public record CriticalResourceDto(
            NodeDto resource,
            int riskScore,
            int affectedSecretCount,
            int findingCount,
            String reason
    ) {
    }
}