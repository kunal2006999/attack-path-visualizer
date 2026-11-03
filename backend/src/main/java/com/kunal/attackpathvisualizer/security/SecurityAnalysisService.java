package com.kunal.attackpathvisualizer.security;

import com.kunal.attackpathvisualizer.core.pipeline.ClusterGraphPipeline;
import com.kunal.attackpathvisualizer.graph.AttackGraph;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@Service
public class SecurityAnalysisService {

    private final AttackPathAnalyzer attackPathAnalyzer;
    private final CriticalResourceAnalyzer criticalResourceAnalyzer;
    private final RecommendationEngine recommendationEngine;

    public SecurityAnalysisService(
            AttackPathAnalyzer attackPathAnalyzer,
            CriticalResourceAnalyzer criticalResourceAnalyzer,
            RecommendationEngine recommendationEngine
    ) {
        this.attackPathAnalyzer = Objects.requireNonNull(
                attackPathAnalyzer,
                "Attack path analyzer cannot be null"
        );

        this.criticalResourceAnalyzer = Objects.requireNonNull(
                criticalResourceAnalyzer,
                "Critical resource analyzer cannot be null"
        );

        this.recommendationEngine = Objects.requireNonNull(
                recommendationEngine,
                "Recommendation engine cannot be null"
        );
    }

    public SecurityReport analyze(
            ClusterGraphPipeline.PipelineResult pipelineResult
    ) {
        Objects.requireNonNull(
                pipelineResult,
                "Pipeline result cannot be null"
        );

        AttackGraph graph = pipelineResult.graph();

        if (graph == null) {
            throw new IllegalArgumentException(
                    "Pipeline result must contain a graph"
            );
        }

        List<Finding> initialFindings =
                attackPathAnalyzer.analyze(pipelineResult);

        List<Finding> findings = applyRecommendations(initialFindings);

        List<CriticalResource> criticalResources =
                criticalResourceAnalyzer.analyze(graph, findings);

        Map<Severity, Integer> severityCounts =
                calculateSeverityCounts(findings);

        return new SecurityReport(
                Instant.now(),
                findings.size(),
                severityCounts,
                findings,
                criticalResources
        );
    }

    private List<Finding> applyRecommendations(
            List<Finding> initialFindings
    ) {
        List<Finding> updatedFindings = new ArrayList<>();

        for (Finding finding : initialFindings) {
            String recommendation = recommendationEngine.recommend(finding);

            updatedFindings.add(
                    new Finding(
                            finding.id(),
                            finding.title(),
                            finding.description(),
                            finding.entryPoint(),
                            finding.target(),
                            finding.attackPath(),
                            finding.riskScore(),
                            finding.severity(),
                            finding.scoreFactors(),
                            recommendation
                    )
            );
        }

        return List.copyOf(updatedFindings);
    }

    private Map<Severity, Integer> calculateSeverityCounts(
            List<Finding> findings
    ) {
        Map<Severity, Integer> counts =
                new EnumMap<>(Severity.class);

        for (Severity severity : Severity.values()) {
            counts.put(severity, 0);
        }

        for (Finding finding : findings) {
            counts.merge(
                    finding.severity(),
                    1,
                    Integer::sum
            );
        }

        return counts;
    }
}