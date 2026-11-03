package com.kunal.attackpathvisualizer.security;

import com.kunal.attackpathvisualizer.analysis.BlastRadiusAnalyzer;
import com.kunal.attackpathvisualizer.analysis.BlastRadiusResult;
import com.kunal.attackpathvisualizer.graph.AttackGraph;
import com.kunal.attackpathvisualizer.graph.GraphNode;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

@Component
public class CriticalResourceAnalyzer {

    public List<CriticalResource> analyze(
            AttackGraph graph,
            List<Finding> findings
    ) {
        Objects.requireNonNull(graph, "Graph cannot be null");
        Objects.requireNonNull(findings, "Findings cannot be null");

        Map<GraphNode, Integer> findingCounts = new HashMap<>();
        Map<GraphNode, Set<GraphNode>> secretsByResource = new HashMap<>();

        for (Finding finding : findings) {
            Objects.requireNonNull(finding, "Finding cannot be null");

            for (GraphNode node : finding.attackPath()) {
                findingCounts.merge(node, 1, Integer::sum);
            }
        }

        BlastRadiusAnalyzer blastRadiusAnalyzer =
                new BlastRadiusAnalyzer(graph);

        for (GraphNode node : graph.getNodes()) {
            BlastRadiusResult result =
                    blastRadiusAnalyzer.BlastRadius(node.getId());

            Set<GraphNode> reachableSecrets = new HashSet<>();

            for (GraphNode affected : result.getAffectedNodes()) {
                if (isSecret(affected)) {
                    reachableSecrets.add(affected);
                }
            }

            if (!reachableSecrets.isEmpty()) {
                secretsByResource.put(node, reachableSecrets);
            }
        }

        List<CriticalResource> criticalResources = new ArrayList<>();

        for (GraphNode node : graph.getNodes()) {
            int findingCount = findingCounts.getOrDefault(node, 0);

            int affectedSecretCount = secretsByResource
                    .getOrDefault(node, Set.of())
                    .size();

            boolean isClusterRoleBinding =
                    node.getResourceType() != null
                            && node.getResourceType().name()
                            .equals("CLUSTER_ROLE_BINDING");

            if (findingCount == 0
                    && affectedSecretCount == 0
                    && !isClusterRoleBinding) {
                continue;
            }

            int score = calculateCriticalityScore(
                    findingCount,
                    affectedSecretCount,
                    isClusterRoleBinding
            );

            String reason = buildReason(
                    findingCount,
                    affectedSecretCount,
                    isClusterRoleBinding
            );

            criticalResources.add(
                    new CriticalResource(
                            node,
                            score,
                            affectedSecretCount,
                            findingCount,
                            reason
                    )
            );
        }

        criticalResources.sort(
                Comparator.comparingInt(
                                CriticalResource::riskScore
                        ).reversed()
                        .thenComparing(
                                resource -> resource.resource().getId()
                        )
        );

        return List.copyOf(criticalResources);
    }

    private int calculateCriticalityScore(
            int findingCount,
            int affectedSecretCount,
            boolean isClusterRoleBinding
    ) {
        int score = 0;

        score += Math.min(findingCount * 15, 45);
        score += Math.min(affectedSecretCount * 10, 40);

        if (isClusterRoleBinding) {
            score += 15;
        }

        return Math.min(score, 100);
    }

    private String buildReason(
            int findingCount,
            int affectedSecretCount,
            boolean isClusterRoleBinding
    ) {
        List<String> reasons = new ArrayList<>();

        if (findingCount > 0) {
            reasons.add(
                    "Appears in " + findingCount + " security finding(s)"
            );
        }

        if (affectedSecretCount > 0) {
            reasons.add(
                    "Can reach " + affectedSecretCount + " Secret node(s)"
            );
        }

        if (isClusterRoleBinding) {
            reasons.add(
                    "Is a ClusterRoleBinding requiring permission-scope review"
            );
        }

        return String.join("; ", reasons);
    }

    private boolean isSecret(GraphNode node) {
        return node != null
                && node.getResourceType() != null
                && node.getResourceType().name().equals("SECRET");
    }
}