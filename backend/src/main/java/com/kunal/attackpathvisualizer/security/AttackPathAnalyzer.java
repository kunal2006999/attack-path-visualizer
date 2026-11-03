package com.kunal.attackpathvisualizer.security;

import com.kunal.attackpathvisualizer.analysis.DijkstraAnalyzer;
import com.kunal.attackpathvisualizer.analysis.DijkstraResult;
import com.kunal.attackpathvisualizer.core.model.Cluster;
import com.kunal.attackpathvisualizer.core.model.ClusterRole;
import com.kunal.attackpathvisualizer.core.model.ClusterRoleBinding;
import com.kunal.attackpathvisualizer.core.model.KubernetesResource;
import com.kunal.attackpathvisualizer.core.model.RbacRule;
import com.kunal.attackpathvisualizer.core.model.Role;
import com.kunal.attackpathvisualizer.core.model.RoleBinding;
import com.kunal.attackpathvisualizer.core.model.Secret;
import com.kunal.attackpathvisualizer.core.pipeline.ClusterGraphPipeline;
import com.kunal.attackpathvisualizer.core.relation.RelationshipType;
import com.kunal.attackpathvisualizer.graph.AttackGraph;
import com.kunal.attackpathvisualizer.graph.GraphEdge;
import com.kunal.attackpathvisualizer.graph.GraphNode;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Identifies modeled Pod-to-Secret access paths and produces security findings.
 *
 * <h3>Scoring formula</h3>
 * <pre>
 *   SECRET_SENSITIVITY   : 0–40  (SecretSensitivityClassifier)
 *   PERMISSION_SCOPE     : 10–30 (Role=10, RoleBinding=15, ClusterRole=20, ClusterRoleBinding=30)
 *   WILDCARD_PERMISSION  : 0–25  (0=none, 10=partial wildcards, 25=fully wildcarded rules)
 *   ATTACK_PATH_LENGTH   : 0–5   (shorter path = higher risk)
 *   Maximum possible     : 100   (all four factors at maximum)
 * </pre>
 *
 * <h3>What this class does NOT do</h3>
 * <ul>
 *   <li>Evaluate User or Group subjects (only ServiceAccount subjects are modeled).</li>
 *   <li>Handle subresources, nonResourceURLs, aggregated ClusterRoles, or label selectors.</li>
 *   <li>Confirm live exploitability — findings describe modeled access paths only.</li>
 * </ul>
 */
@Component
public class AttackPathAnalyzer {

    private final SecretSensitivityClassifier sensitivityClassifier;
    private final RiskScorer riskScorer;

    public AttackPathAnalyzer(
            SecretSensitivityClassifier sensitivityClassifier,
            RiskScorer riskScorer
    ) {
        this.sensitivityClassifier = Objects.requireNonNull(
                sensitivityClassifier,
                "Sensitivity classifier cannot be null"
        );

        this.riskScorer = Objects.requireNonNull(
                riskScorer,
                "Risk scorer cannot be null"
        );
    }

    /**
     * Identifies modeled Pod-to-Secret access paths in a pipeline result.
     *
     * <p>A finding is generated for each distinct (Pod, CAN_ACCESS edge) pair
     * where the Pod can reach the source of that edge in the directed graph.
     * Each finding represents a separate grant of access to the Secret.
     *
     * <p>The {@code recommendation} field of each returned finding contains a
     * placeholder. Callers should replace it using {@link RecommendationEngine}
     * before surfacing findings to users.
     */
    public List<Finding> analyze(
            ClusterGraphPipeline.PipelineResult pipelineResult
    ) {
        Objects.requireNonNull(
                pipelineResult,
                "Pipeline result cannot be null"
        );

        Cluster cluster = pipelineResult.cluster();
        AttackGraph graph = pipelineResult.graph();

        if (cluster == null || graph == null) {
            throw new IllegalArgumentException(
                    "Pipeline result must contain a cluster and graph"
            );
        }

        ResourceIndex resourceIndex = new ResourceIndex(cluster);

        List<GraphNode> pods = graph.getNodes()
                .stream()
                .filter(node -> hasType(node, "POD"))
                .sorted(Comparator.comparing(GraphNode::getId))
                .toList();

        List<GraphEdge> accessEdges = graph.getNodes()
                .stream()
                .flatMap(node -> graph.getOutgoingEdges(node.getId()).stream())
                .filter(edge ->
                        edge.getRelationshipType() == RelationshipType.CAN_ACCESS
                )
                .filter(edge ->
                        hasType(edge.getTarget(), "SECRET")
                )
                .sorted(
                        Comparator.comparing(
                                (GraphEdge edge) -> edge.getSource().getId()
                        ).thenComparing(
                                edge -> edge.getTarget().getId()
                        )
                )
                .toList();

        List<Finding> findings = new ArrayList<>();

        /*
         * Run Dijkstra once per Pod, rather than once per access edge.
         * Each (Pod, CAN_ACCESS edge) pair that forms a valid path becomes
         * one distinct finding, even if multiple grants reach the same Secret.
         */
        for (GraphNode pod : pods) {
            DijkstraAnalyzer dijkstra = new DijkstraAnalyzer(graph);

            DijkstraResult result = dijkstra.shortestDistances(
                    pod.getId()
            );

            for (GraphEdge accessEdge : accessEdges) {
                GraphNode grantSource = accessEdge.getSource();
                GraphNode secretNode = accessEdge.getTarget();

                /*
                 * The Pod must be able to reach the source of the
                 * CAN_ACCESS edge in the directed graph.
                 */
                if (!result.getDistances().containsKey(grantSource)) {
                    continue;
                }

                /*
                 * Resolve the target to the original Secret model.
                 */
                Secret secret = resourceIndex.findByNode(
                        secretNode,
                        Secret.class
                ).orElse(null);

                if (secret == null) {
                    continue;
                }

                List<GraphNode> path = reconstructPath(
                        pod,
                        grantSource,
                        result.getPrevious()
                );

                if (path.isEmpty()) {
                    continue;
                }

                /*
                 * Append the Secret because grantSource -> Secret
                 * is the CAN_ACCESS edge being analyzed.
                 */
                path.add(secretNode);

                findings.add(
                        createFinding(
                                pod,
                                secretNode,
                                secret,
                                grantSource,
                                path,
                                resourceIndex
                        )
                );
            }
        }

        return List.copyOf(findings);
    }

    /**
     * Reconstructs the shortest path from the starting Pod
     * to the source of a CAN_ACCESS edge.
     *
     * Returns an empty list if reconstruction fails or a cycle is detected.
     */
    private List<GraphNode> reconstructPath(
            GraphNode start,
            GraphNode destination,
            Map<GraphNode, GraphNode> previous
    ) {
        List<GraphNode> reversedPath = new ArrayList<>();

        GraphNode current = destination;

        /*
         * Protect against malformed predecessor chains (cycles).
         */
        Map<GraphNode, Boolean> visited = new HashMap<>();

        while (current != null) {
            if (visited.put(current, Boolean.TRUE) != null) {
                return List.of();
            }

            reversedPath.add(current);

            if (current.equals(start)) {
                Collections.reverse(reversedPath);
                return reversedPath;
            }

            current = previous.get(current);
        }

        return List.of();
    }

    private Finding createFinding(
            GraphNode pod,
            GraphNode secretNode,
            Secret secret,
            GraphNode grantSource,
            List<GraphNode> path,
            ResourceIndex resourceIndex
    ) {
        int sensitivityScore = sensitivityClassifier.classify(secret);

        List<ScoreFactor> factors = new ArrayList<>();

        factors.add(
                new ScoreFactor(
                        "SECRET_SENSITIVITY",
                        sensitivityScore,
                        "Estimated Secret sensitivity based on its type, "
                                + "name, labels, and namespace."
                )
        );

        addPermissionScopeFactor(grantSource, factors);

        addWildcardPermissionFactor(grantSource, resourceIndex, factors);

        addPathLengthFactor(path, factors);

        int riskScore = riskScorer.calculateScore(factors);

        Severity severity = riskScorer.calculateSeverity(riskScore);

        /*
         * A placeholder recommendation is used here. SecurityAnalysisService
         * replaces it with the output of RecommendationEngine before returning
         * findings to callers.
         */
        String recommendation =
                "Review the modeled Secret access and verify that the "
                        + "grant is required and follows least privilege.";

        String title = "Pod can reach Secret: " + secretNode.getName();

        String description = String.format(
                "The modeled graph contains a directed path from Pod '%s' "
                        + "to Secret '%s', ending with a CAN_ACCESS edge "
                        + "from '%s'. This indicates modeled Secret access "
                        + "according to the collected cluster relationships "
                        + "and RBAC rules.",
                pod.getName(),
                secretNode.getName(),
                grantSource.getName()
        );

        return new Finding(
                null,
                title,
                description,
                pod,
                secretNode,
                path,
                riskScore,
                severity,
                factors,
                recommendation
        );
    }

    /**
     * Adds the PERMISSION_SCOPE factor based on the type of the grant-source node.
     *
     * <pre>
     *   ROLE                 → 10  (namespaced, narrowest scope)
     *   ROLE_BINDING         → 15  (namespaced binding; references Role or ClusterRole)
     *   CLUSTER_ROLE         → 20  (cluster-scoped rules; scope depends on binding)
     *   CLUSTER_ROLE_BINDING → 30  (cluster-wide grant; highest scope)
     *   other                → 10  (unknown; conservative estimate)
     * </pre>
     *
     * A RoleBinding referencing a ClusterRole still receives the ROLE_BINDING score
     * because the binding itself limits the effective scope to its namespace.
     */
    private void addPermissionScopeFactor(
            GraphNode grantSource,
            List<ScoreFactor> factors
    ) {
        Objects.requireNonNull(
                grantSource,
                "Grant source cannot be null"
        );

        String resourceType = grantSource.getResourceType().name();

        switch (resourceType) {
            case "CLUSTER_ROLE_BINDING" ->
                    factors.add(
                            new ScoreFactor(
                                    "PERMISSION_SCOPE",
                                    30,
                                    "The access edge originates from a "
                                            + "ClusterRoleBinding, which grants "
                                            + "permissions cluster-wide to the "
                                            + "referenced ClusterRole's rules."
                            )
                    );

            case "ROLE_BINDING" ->
                    factors.add(
                            new ScoreFactor(
                                    "PERMISSION_SCOPE",
                                    15,
                                    "The access edge originates from a "
                                            + "RoleBinding, which limits the "
                                            + "binding's permissions to its "
                                            + "namespace, even when it references "
                                            + "a ClusterRole."
                            )
                    );

            case "ROLE" ->
                    factors.add(
                            new ScoreFactor(
                                    "PERMISSION_SCOPE",
                                    10,
                                    "The access edge originates from a "
                                            + "namespaced Role. Its rules are "
                                            + "scoped to the Role's namespace."
                            )
                    );

            case "CLUSTER_ROLE" ->
                    factors.add(
                            new ScoreFactor(
                                    "PERMISSION_SCOPE",
                                    20,
                                    "The access edge originates from a "
                                            + "ClusterRole. Effective scope depends "
                                            + "on the binding through which it "
                                            + "is granted."
                            )
                    );

            default ->
                    factors.add(
                            new ScoreFactor(
                                    "PERMISSION_SCOPE",
                                    10,
                                    "Secret access is modeled through "
                                            + resourceType
                                            + "; effective permission scope "
                                            + "requires further verification."
                            )
                    );
        }
    }

    /**
     * Adds the WILDCARD_PERMISSION factor by inspecting the RBAC rules that
     * produced the CAN_ACCESS edge.
     *
     * <p>Scoring:
     * <ul>
     *   <li>25 — fully wildcarded: all of apiGroups, resources, and verbs contain {@code *}.</li>
     *   <li>10 — partially wildcarded: at least one of apiGroups, resources, or verbs is {@code *}.</li>
     *   <li> 0 — no wildcards: all fields contain only explicit values.</li>
     * </ul>
     *
     * <p>For a RoleBinding, the rules examined are those of the directly referenced
     * Role or ClusterRole (since the binding itself has no rules). For a
     * ClusterRoleBinding, the rules of the referenced ClusterRole are examined.
     * For a Role or ClusterRole node, its own rules are examined.
     *
     * <p>If the rules cannot be resolved (e.g. the referenced role is absent
     * from the ResourceIndex), 0 points are awarded — the absence of evidence
     * is not evidence of wildcards.
     */
    private void addWildcardPermissionFactor(
            GraphNode grantSource,
            ResourceIndex resourceIndex,
            List<ScoreFactor> factors
    ) {
        List<RbacRule> rules = resolveRules(grantSource, resourceIndex);

        if (rules == null || rules.isEmpty()) {
            factors.add(new ScoreFactor(
                    "WILDCARD_PERMISSION",
                    0,
                    "No RBAC rules could be resolved for the grant source; "
                            + "wildcard analysis skipped."
            ));
            return;
        }

        boolean fullyWildcarded = rules.stream()
                .anyMatch(AttackPathAnalyzer::isFullyWildcarded);

        boolean partiallyWildcarded = rules.stream()
                .anyMatch(AttackPathAnalyzer::hasAnyWildcard);

        if (fullyWildcarded) {
            factors.add(new ScoreFactor(
                    "WILDCARD_PERMISSION",
                    25,
                    "At least one RBAC rule grants wildcard apiGroups (*), "
                            + "resources (*), and verbs (*), giving unrestricted access."
            ));
        } else if (partiallyWildcarded) {
            factors.add(new ScoreFactor(
                    "WILDCARD_PERMISSION",
                    10,
                    "At least one RBAC rule uses a wildcard (*) in apiGroups, "
                            + "resources, or verbs, broadening the grant scope."
            ));
        } else {
            factors.add(new ScoreFactor(
                    "WILDCARD_PERMISSION",
                    0,
                    "No wildcard permissions detected; rules use explicit "
                            + "apiGroups, resources, and verbs."
            ));
        }
    }

    /**
     * Resolves the RBAC rules that are responsible for the CAN_ACCESS edge
     * originating from {@code grantSource}.
     *
     * <p>Returns {@code null} when the grant source's rules cannot be resolved.
     */
    private List<RbacRule> resolveRules(
            GraphNode grantSource,
            ResourceIndex resourceIndex
    ) {
        KubernetesResource resource = resourceIndex
                .findByNode(grantSource)
                .orElse(null);

        if (resource == null) {
            return null;
        }

        if (resource instanceof Role role) {
            return role.getRules();
        }

        if (resource instanceof ClusterRole clusterRole) {
            return clusterRole.getRules();
        }

        if (resource instanceof RoleBinding rb) {
            /*
             * A RoleBinding delegates its effective permissions to the
             * referenced Role or ClusterRole. Roles are namespaced, so a
             * referenced Role must live in the binding's own namespace.
             * ClusterRoles are cluster-scoped and matched by name only.
             */
            if ("ClusterRole".equals(rb.getRoleKind())) {
                ClusterRole cr = resourceIndex.getAllResources()
                        .stream()
                        .filter(r -> r instanceof ClusterRole)
                        .map(r -> (ClusterRole) r)
                        .filter(r -> Objects.equals(rb.getRoleName(), r.getName()))
                        .findFirst()
                        .orElse(null);
                return cr != null ? cr.getRules() : null;
            } else {
                Role role = resourceIndex.getAllResources()
                        .stream()
                        .filter(r -> r instanceof Role)
                        .map(r -> (Role) r)
                        .filter(r -> Objects.equals(rb.getNamespace(), r.getNamespace())
                                && Objects.equals(rb.getRoleName(), r.getName()))
                        .findFirst()
                        .orElse(null);
                return role != null ? role.getRules() : null;
            }
        }

        if (resource instanceof ClusterRoleBinding crb) {
            ClusterRole cr = resourceIndex.getAllResources()
                    .stream()
                    .filter(r -> r instanceof ClusterRole)
                    .map(r -> (ClusterRole) r)
                    .filter(r -> Objects.equals(crb.getClusterRoleName(), r.getName()))
                    .findFirst()
                    .orElse(null);
            return cr != null ? cr.getRules() : null;
        }

        return null;
    }

    /**
     * Returns {@code true} when the rule has wildcard values in all of
     * apiGroups, resources, and verbs simultaneously.
     */
    private static boolean isFullyWildcarded(RbacRule rule) {
        if (rule == null) {
            return false;
        }
        return containsWildcard(rule.getApiGroups())
                && containsWildcard(rule.getResources())
                && containsWildcard(rule.getVerbs());
    }

    /**
     * Returns {@code true} when the rule has a wildcard in at least one of
     * apiGroups, resources, or verbs.
     */
    private static boolean hasAnyWildcard(RbacRule rule) {
        if (rule == null) {
            return false;
        }
        return containsWildcard(rule.getApiGroups())
                || containsWildcard(rule.getResources())
                || containsWildcard(rule.getVerbs());
    }

    private static boolean containsWildcard(List<String> list) {
        return list != null && list.contains("*");
    }

    private void addPathLengthFactor(
            List<GraphNode> path,
            List<ScoreFactor> factors
    ) {
        int edgeCount = path.size() - 1;

        int points;

        if (edgeCount <= 3) {
            points = 5;
        } else if (edgeCount <= 5) {
            points = 3;
        } else if (edgeCount <= 7) {
            points = 1;
        } else {
            points = 0;
        }

        factors.add(
                new ScoreFactor(
                        "ATTACK_PATH_LENGTH",
                        points,
                        "The modeled path contains "
                                + edgeCount
                                + " edge(s). Shorter paths indicate more direct access."
                )
        );
    }

    private boolean hasType(GraphNode node, String expectedType) {
        return node != null
                && node.getResourceType() != null
                && node.getResourceType().name().equals(expectedType);
    }
}