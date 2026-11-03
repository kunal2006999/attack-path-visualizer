package com.kunal.attackpathvisualizer.security;

import com.kunal.attackpathvisualizer.core.enums.ResourceType;
import com.kunal.attackpathvisualizer.core.relation.RelationshipType;
import com.kunal.attackpathvisualizer.graph.AttackGraph;
import com.kunal.attackpathvisualizer.graph.GraphEdge;
import com.kunal.attackpathvisualizer.graph.GraphNode;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link CriticalResourceAnalyzer}.
 *
 * <p>Tests cover: multiple findings on one resource, multiple affected secrets,
 * isolated resources, correct ranking, ClusterRoleBinding escalation, and
 * null input rejection.
 */
class CriticalResourceAnalyzerTest {

    private CriticalResourceAnalyzer analyzer;

    @BeforeEach
    void setUp() {
        analyzer = new CriticalResourceAnalyzer();
    }

    /* ------------------------------------------------------------------ */
    /* Scenario: empty graph, no findings → no critical resources          */
    /* ------------------------------------------------------------------ */

    @Test
    void emptyGraphAndNoFindingsProduceNoCriticalResources() {
        AttackGraph graph = new AttackGraph();
        List<CriticalResource> result = analyzer.analyze(graph, List.of());
        assertTrue(result.isEmpty(), "Empty inputs must produce no critical resources");
    }

    /* ------------------------------------------------------------------ */
    /* Scenario: one finding, one secret-reachable node                    */
    /* ------------------------------------------------------------------ */

    @Test
    void singleFindingProducesOneCriticalResource() {
        AttackGraph graph = new AttackGraph();

        GraphNode podNode = node("pod-1", ResourceType.POD, "my-pod");
        GraphNode rbNode = node("rb-1", ResourceType.ROLE_BINDING, "my-rb");
        GraphNode secretNode = node("s-1", ResourceType.SECRET, "my-secret");

        graph.addEdge(new GraphEdge(podNode, rbNode, RelationshipType.HAS_BINDING, 1));
        graph.addEdge(new GraphEdge(rbNode, secretNode, RelationshipType.CAN_ACCESS, 1));

        Finding finding = fakeFinding(podNode, secretNode,
                List.of(podNode, rbNode, secretNode));

        List<CriticalResource> result = analyzer.analyze(graph, List.of(finding));

        assertFalse(result.isEmpty(), "At least one critical resource expected");

        // Every returned critical resource must have valid scores and counts.
        for (CriticalResource cr : result) {
            assertTrue(cr.riskScore() >= 0 && cr.riskScore() <= 100,
                    "Risk score must be in [0,100]");
            assertTrue(cr.affectedSecretCount() >= 0);
            assertTrue(cr.findingCount() >= 0);
            assertFalse(cr.reason().isBlank(), "Reason must not be blank");
        }
    }

    /* ------------------------------------------------------------------ */
    /* Scenario: multiple findings on the same node inflate finding count  */
    /* ------------------------------------------------------------------ */

    @Test
    void multipleFindingsOnSameNodeIncreaseItsScore() {
        AttackGraph graph = new AttackGraph();

        GraphNode rbNode = node("rb-1", ResourceType.ROLE_BINDING, "shared-rb");
        GraphNode secret1 = node("s-1", ResourceType.SECRET, "secret-a");
        GraphNode secret2 = node("s-2", ResourceType.SECRET, "secret-b");

        graph.addEdge(new GraphEdge(rbNode, secret1, RelationshipType.CAN_ACCESS, 1));
        graph.addEdge(new GraphEdge(rbNode, secret2, RelationshipType.CAN_ACCESS, 1));

        // Two findings, each passing through rbNode
        Finding f1 = fakeFinding(rbNode, secret1, List.of(rbNode, secret1));
        Finding f2 = fakeFinding(rbNode, secret2, List.of(rbNode, secret2));

        List<CriticalResource> result = analyzer.analyze(graph, List.of(f1, f2));

        CriticalResource rbCr = result.stream()
                .filter(cr -> cr.resource().getName().equals("shared-rb"))
                .findFirst()
                .orElse(null);

        assertNotNull(rbCr, "Shared RoleBinding must appear as a critical resource");
        assertTrue(rbCr.findingCount() >= 2,
                "Finding count must reflect both findings");
    }

    /* ------------------------------------------------------------------ */
    /* Scenario: multiple Secrets reachable from one node                  */
    /* ------------------------------------------------------------------ */

    @Test
    void nodeReachingMultipleSecretsHasHighAffectedSecretCount() {
        AttackGraph graph = new AttackGraph();

        GraphNode crbNode = node("crb-1", ResourceType.CLUSTER_ROLE_BINDING, "admin-crb");
        GraphNode s1 = node("s-1", ResourceType.SECRET, "secret-1");
        GraphNode s2 = node("s-2", ResourceType.SECRET, "secret-2");
        GraphNode s3 = node("s-3", ResourceType.SECRET, "secret-3");

        graph.addEdge(new GraphEdge(crbNode, s1, RelationshipType.CAN_ACCESS, 1));
        graph.addEdge(new GraphEdge(crbNode, s2, RelationshipType.CAN_ACCESS, 1));
        graph.addEdge(new GraphEdge(crbNode, s3, RelationshipType.CAN_ACCESS, 1));

        List<CriticalResource> result = analyzer.analyze(graph, List.of());

        CriticalResource crbCr = result.stream()
                .filter(cr -> cr.resource().getName().equals("admin-crb"))
                .findFirst()
                .orElse(null);

        assertNotNull(crbCr, "ClusterRoleBinding must appear as a critical resource");
        assertEquals(3, crbCr.affectedSecretCount(),
                "All three reachable Secrets must be counted");
    }

    /* ------------------------------------------------------------------ */
    /* Scenario: isolated node (no findings, no reachable secrets)         */
    /* → must NOT appear in critical resources                             */
    /* ------------------------------------------------------------------ */

    @Test
    void isolatedNonClusterRoleBindingNodeIsExcluded() {
        AttackGraph graph = new AttackGraph();

        GraphNode isolatedPod = node("pod-1", ResourceType.POD, "lonely-pod");
        graph.addNode(isolatedPod);

        List<CriticalResource> result = analyzer.analyze(graph, List.of());

        boolean containsIsolatedPod = result.stream()
                .anyMatch(cr -> cr.resource().getName().equals("lonely-pod"));

        assertFalse(containsIsolatedPod,
                "Isolated Pod with no findings and no reachable Secrets must be excluded");
    }

    /* ------------------------------------------------------------------ */
    /* Scenario: ClusterRoleBinding is included even with no findings      */
    /* ------------------------------------------------------------------ */

    @Test
    void clusterRoleBindingWithoutFindingsIsIncluded() {
        AttackGraph graph = new AttackGraph();

        GraphNode crb = node("crb-1", ResourceType.CLUSTER_ROLE_BINDING, "orphan-crb");
        graph.addNode(crb);

        List<CriticalResource> result = analyzer.analyze(graph, List.of());

        boolean containsCrb = result.stream()
                .anyMatch(cr -> cr.resource().getName().equals("orphan-crb"));

        assertTrue(containsCrb,
                "ClusterRoleBinding must be included even with no findings");
    }

    /* ------------------------------------------------------------------ */
    /* Scenario: results are ordered by risk score descending              */
    /* ------------------------------------------------------------------ */

    @Test
    void resultsAreOrderedByRiskScoreDescending() {
        AttackGraph graph = new AttackGraph();

        // High-risk: CRB with many findings
        GraphNode crb = node("crb-1", ResourceType.CLUSTER_ROLE_BINDING, "high-risk-crb");
        GraphNode s1 = node("s-1", ResourceType.SECRET, "secret-1");
        GraphNode s2 = node("s-2", ResourceType.SECRET, "secret-2");

        graph.addEdge(new GraphEdge(crb, s1, RelationshipType.CAN_ACCESS, 1));
        graph.addEdge(new GraphEdge(crb, s2, RelationshipType.CAN_ACCESS, 1));

        // Low-risk: isolated CRB with no secrets
        GraphNode lowRiskCrb = node("crb-2", ResourceType.CLUSTER_ROLE_BINDING, "low-risk-crb");
        graph.addNode(lowRiskCrb);

        Finding f1 = fakeFinding(crb, s1, List.of(crb, s1));
        Finding f2 = fakeFinding(crb, s2, List.of(crb, s2));

        List<CriticalResource> result = analyzer.analyze(graph, List.of(f1, f2));

        assertFalse(result.isEmpty());

        // Verify non-increasing order by risk score
        for (int i = 1; i < result.size(); i++) {
            assertTrue(
                    result.get(i - 1).riskScore() >= result.get(i).riskScore(),
                    "Critical resources must be ordered by risk score descending"
            );
        }
    }

    /* ------------------------------------------------------------------ */
    /* Scenario: null inputs rejected                                       */
    /* ------------------------------------------------------------------ */

    @Test
    void nullGraphIsRejected() {
        assertThrows(NullPointerException.class,
                () -> analyzer.analyze(null, List.of()));
    }

    @Test
    void nullFindingsListIsRejected() {
        assertThrows(NullPointerException.class,
                () -> analyzer.analyze(new AttackGraph(), null));
    }

    /* ------------------------------------------------------------------ */
    /* Scenario: scores stay in [0,100]                                    */
    /* ------------------------------------------------------------------ */

    @Test
    void criticalResourceScoresAreAlwaysInValidRange() {
        AttackGraph graph = new AttackGraph();

        GraphNode crb = node("crb-1", ResourceType.CLUSTER_ROLE_BINDING, "admin-crb");
        for (int i = 1; i <= 10; i++) {
            GraphNode s = node("s-" + i, ResourceType.SECRET, "secret-" + i);
            graph.addEdge(new GraphEdge(crb, s, RelationshipType.CAN_ACCESS, 1));
        }

        // Create 10 findings through crb
        List<Finding> findings = graph.getOutgoingEdges("crb-1").stream()
                .map(e -> fakeFinding(crb, e.getTarget(),
                        List.of(crb, e.getTarget())))
                .toList();

        List<CriticalResource> result = analyzer.analyze(graph, findings);

        for (CriticalResource cr : result) {
            assertTrue(cr.riskScore() >= 0 && cr.riskScore() <= 100,
                    "Risk score must always be in [0,100]");
        }
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                             */
    /* ------------------------------------------------------------------ */

    private static GraphNode node(String id, ResourceType type, String name) {
        return new GraphNode(id, id, type, name, null);
    }

    private static Finding fakeFinding(
            GraphNode entry,
            GraphNode target,
            List<GraphNode> path) {

        List<ScoreFactor> factors = List.of(
                new ScoreFactor("TEST", 20, "Test factor")
        );

        return new Finding(
                "test-" + entry.getId() + "-" + target.getId(),
                "Test Finding: " + entry.getName() + " → " + target.getName(),
                "Modeled path from " + entry.getName() + " to " + target.getName() + ".",
                entry,
                target,
                path,
                20,
                Severity.LOW,
                factors,
                "Review the modeled access."
        );
    }
}
