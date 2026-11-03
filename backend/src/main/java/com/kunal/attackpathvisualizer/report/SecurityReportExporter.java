package com.kunal.attackpathvisualizer.report;

import com.kunal.attackpathvisualizer.graph.GraphNode;
import com.kunal.attackpathvisualizer.report.SecurityReportDto.CriticalResourceDto;
import com.kunal.attackpathvisualizer.report.SecurityReportDto.FindingDto;
import com.kunal.attackpathvisualizer.report.SecurityReportDto.NodeDto;
import com.kunal.attackpathvisualizer.report.SecurityReportDto.ScoreFactorDto;
import com.kunal.attackpathvisualizer.security.CriticalResource;
import com.kunal.attackpathvisualizer.security.Finding;
import com.kunal.attackpathvisualizer.security.ScoreFactor;
import com.kunal.attackpathvisualizer.security.SecurityReport;
import com.kunal.attackpathvisualizer.security.Severity;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Serializes a {@link SecurityReport} to JSON. Pure mapping; no analysis logic.
 */
@Component
public class SecurityReportExporter {

    private final ObjectMapper objectMapper;

    public SecurityReportExporter() {
        this.objectMapper = new ObjectMapper();
    }

    public String export(SecurityReport report) {
        return export(null, report);
    }

    public String export(String clusterName, SecurityReport report) {
        Objects.requireNonNull(report, "Security report cannot be null");

        SecurityReportDto dto = toDto(clusterName, report);

        try {
            return objectMapper
                    .writerWithDefaultPrettyPrinter()
                    .writeValueAsString(dto);
        } catch (JacksonException e) {
            throw new IllegalStateException(
                    "Failed to export security report as JSON", e);
        }
    }

    public SecurityReportDto toDto(String clusterName, SecurityReport report) {
        Objects.requireNonNull(report, "Security report cannot be null");

        return new SecurityReportDto(
                clusterName,
                report.generatedAt().toString(),
                report.totalFindings(),
                completeSeverityCounts(report.severityCounts()),
                report.findings().stream().map(this::toFindingDto).toList(),
                report.criticalResources().stream()
                        .map(this::toCriticalResourceDto)
                        .toList()
        );
    }

    /** Always contains every severity, in declaration order, defaulting to 0. */
    private Map<String, Integer> completeSeverityCounts(
            Map<Severity, Integer> counts) {
        Map<String, Integer> result = new LinkedHashMap<>();
        for (Severity severity : Severity.values()) {
            result.put(severity.name(), counts.getOrDefault(severity, 0));
        }
        return result;
    }

    private FindingDto toFindingDto(Finding finding) {
        List<ScoreFactorDto> factors = finding.scoreFactors().stream()
                .map(this::toScoreFactorDto)
                .toList();

        return new FindingDto(
                finding.id(),
                finding.title(),
                finding.description(),
                toNodeDto(finding.entryPoint()),
                toNodeDto(finding.target()),
                finding.attackPath().stream().map(this::toNodeDto).toList(),
                finding.riskScore(),
                finding.severity().name(),
                factors,
                finding.recommendation()
        );
    }

    private ScoreFactorDto toScoreFactorDto(ScoreFactor factor) {
        return new ScoreFactorDto(
                factor.name(), factor.points(), factor.reason());
    }

    private CriticalResourceDto toCriticalResourceDto(CriticalResource cr) {
        return new CriticalResourceDto(
                toNodeDto(cr.resource()),
                cr.riskScore(),
                cr.affectedSecretCount(),
                cr.findingCount(),
                cr.reason()
        );
    }

    private NodeDto toNodeDto(GraphNode node) {
        return new NodeDto(
                node.getId(),
                node.getResourceId(),
                node.getResourceType() == null
                        ? null
                        : node.getResourceType().name(),
                node.getName(),
                node.getNamespace()
        );
    }
}