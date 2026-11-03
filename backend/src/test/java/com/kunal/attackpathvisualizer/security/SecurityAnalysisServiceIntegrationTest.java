package com.kunal.attackpathvisualizer.security;

import com.kunal.attackpathvisualizer.common.util.ClusterSnapshotParser;
import com.kunal.attackpathvisualizer.core.builder.ClusterSnapshotMapper;
import com.kunal.attackpathvisualizer.core.pipeline.ClusterGraphPipeline;
import com.kunal.attackpathvisualizer.core.validation.ClusterSnapshotValidator;
import com.kunal.attackpathvisualizer.graph.GraphBuilder;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

class SecurityAnalysisServiceIntegrationTest {

    private final ClusterGraphPipeline pipeline =
            new ClusterGraphPipeline(
                    new ClusterSnapshotParser(),
                    new ClusterSnapshotValidator(),
                    new ClusterSnapshotMapper(),
                    new GraphBuilder()
            );

    private final SecurityAnalysisService securityAnalysisService =
            new SecurityAnalysisService(
                    new AttackPathAnalyzer(
                            new SecretSensitivityClassifier(),
                            new RiskScorer()
                    ),
                    new CriticalResourceAnalyzer(),
                    new RecommendationEngine()
            );

    private SecurityReport analyzeFixture(String filename)
            throws IOException {

        var pipelineResult = pipeline.buildFromJson(
                Path.of("sample-data", "clusters", filename)
        );

        return securityAnalysisService.analyze(pipelineResult);
    }

    @Test
    void vulnerableClusterProducesExpectedFindings() throws IOException {

        SecurityReport report =
                analyzeFixture("vulnerable-cluster.json");

        assertEquals(2, report.totalFindings());

        assertEquals(2, report.findings().stream()
                .filter(finding ->
                        finding.entryPoint().getName()
                                .equals("backend-pod"))
                .count());

        assertTrue(report.findings().stream()
                .allMatch(finding ->
                        finding.target().getName()
                                .equals("database-secret")));

        assertTrue(report.findings().stream()
                .allMatch(finding ->
                        !finding.attackPath().isEmpty()));

        assertTrue(report.findings().stream()
                .allMatch(finding ->
                        finding.riskScore() >= 0
                                && finding.riskScore() <= 100));

        assertTrue(report.findings().stream()
                .allMatch(finding ->
                        finding.severity() != null));

        assertTrue(report.findings().stream()
                .allMatch(finding ->
                        !finding.recommendation().isBlank()));
    }

    @Test
    void isolatedClusterProducesNoFindings() throws IOException {

        SecurityReport report =
                analyzeFixture("isolated-resources.json");

        assertEquals(0, report.totalFindings());
        assertTrue(report.findings().isEmpty());

        assertEquals(
                0,
                report.severityCounts().values()
                        .stream()
                        .mapToInt(Integer::intValue)
                        .sum()
        );
    }

    @Test
    void multiPathClusterFindsBothSecrets() throws IOException {

        SecurityReport report =
                analyzeFixture("multi-path-cluster.json");

        Set<String> targetSecrets = report.findings().stream()
                .map(finding -> finding.target().getName())
                .collect(Collectors.toSet());

        assertTrue(
                targetSecrets.contains("secret-a"),
                "Expected a finding targeting secret-a"
        );

        assertTrue(
                targetSecrets.contains("secret-b"),
                "Expected a finding targeting secret-b"
        );
    }

    @Test
    void severityCountsMatchGeneratedFindings() throws IOException {

        SecurityReport report =
                analyzeFixture("vulnerable-cluster.json");

        for (Severity severity : Severity.values()) {
            long expectedCount = report.findings().stream()
                    .filter(finding ->
                            finding.severity() == severity)
                    .count();

            long actualCount = report.severityCounts().getOrDefault(severity, 0);
            assertEquals(expectedCount,
                    actualCount,
                    "Incorrect finding count for " + severity);

        }

        assertEquals(
                report.totalFindings(),
                report.severityCounts().values()
                        .stream()
                        .mapToInt(Integer::intValue)
                        .sum()
        );
    }

    @Test
    void vulnerableClusterProducesCriticalResourceCandidates()
            throws IOException {

        SecurityReport report =
                analyzeFixture("vulnerable-cluster.json");

        assertFalse(
                report.criticalResources().isEmpty(),
                "Expected critical-resource candidates"
        );

        assertTrue(report.criticalResources().stream()
                .allMatch(resource ->
                        resource.riskScore() >= 0
                                && resource.riskScore() <= 100));

        assertTrue(report.criticalResources().stream()
                .anyMatch(resource ->
                        resource.resource().getName()
                                .equals("backend-cluster-admin")));
    }

    @Test
    void isolatedClusterDoesNotReportCriticalResources()
            throws IOException {

        SecurityReport report =
                analyzeFixture("isolated-resources.json");

        assertTrue(
                report.criticalResources().isEmpty(),
                "Expected no critical resources in the isolated fixture"
        );
    }

    @Test
    void reportContainsAllSeverityCategories() throws IOException {

        SecurityReport report =
                analyzeFixture("vulnerable-cluster.json");

        assertEquals(
                Set.of(Severity.values()),
                report.severityCounts().keySet()
        );

        assertNotNull(report.generatedAt());
    }
}