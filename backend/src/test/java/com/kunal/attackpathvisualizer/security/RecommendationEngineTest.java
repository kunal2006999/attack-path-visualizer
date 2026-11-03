package com.kunal.attackpathvisualizer.security;

import com.kunal.attackpathvisualizer.core.enums.ResourceType;
import com.kunal.attackpathvisualizer.graph.GraphNode;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link RecommendationEngine}.
 *
 * <p>Verifies that each supported grant-source type produces a distinct,
 * non-blank recommendation, and that the engine correctly identifies the
 * grant source as the node immediately before the Secret in the attack path.
 */
class RecommendationEngineTest {

    private RecommendationEngine engine;

    @BeforeEach
    void setUp() {
        engine = new RecommendationEngine();
    }

    /* ------------------------------------------------------------------ */
    /* recommendForGrantSource                                              */
    /* ------------------------------------------------------------------ */

    @Test
    void clusterRoleBindingGrantSourceProducesDistinctRecommendation() {
        GraphNode crb = node("crb-1", ResourceType.CLUSTER_ROLE_BINDING, "my-crb");
        String rec = engine.recommendForGrantSource(crb);
        assertNotNull(rec);
        assertFalse(rec.isBlank(), "Recommendation must not be blank");
        assertTrue(rec.toLowerCase().contains("clusterrolebinding")
                || rec.toLowerCase().contains("clusterrole"),
                "Recommendation must mention the grant type");
    }

    @Test
    void roleBindingGrantSourceProducesDistinctRecommendation() {
        GraphNode rb = node("rb-1", ResourceType.ROLE_BINDING, "my-rb");
        String rec = engine.recommendForGrantSource(rb);
        assertNotNull(rec);
        assertFalse(rec.isBlank());
        assertTrue(rec.toLowerCase().contains("rolebinding")
                || rec.toLowerCase().contains("role"),
                "Recommendation must mention the grant type");
    }

    @Test
    void roleGrantSourceProducesDistinctRecommendation() {
        GraphNode role = node("role-1", ResourceType.ROLE, "my-role");
        String rec = engine.recommendForGrantSource(role);
        assertNotNull(rec);
        assertFalse(rec.isBlank());
    }

    @Test
    void clusterRoleGrantSourceProducesDistinctRecommendation() {
        GraphNode cr = node("cr-1", ResourceType.CLUSTER_ROLE, "my-cluster-role");
        String rec = engine.recommendForGrantSource(cr);
        assertNotNull(rec);
        assertFalse(rec.isBlank());
    }

    @Test
    void unknownGrantSourceProducesFallbackRecommendation() {
        GraphNode pod = node("pod-1", ResourceType.POD, "my-pod");
        String rec = engine.recommendForGrantSource(pod);
        assertNotNull(rec);
        assertFalse(rec.isBlank(),
                "Even unknown grant sources must produce a non-blank recommendation");
    }

    @Test
    void allSupportedGrantSourcesProduceDifferentRecommendations() {
        String crbRec = engine.recommendForGrantSource(
                node("crb-1", ResourceType.CLUSTER_ROLE_BINDING, "crb"));
        String rbRec = engine.recommendForGrantSource(
                node("rb-1", ResourceType.ROLE_BINDING, "rb"));
        String roleRec = engine.recommendForGrantSource(
                node("role-1", ResourceType.ROLE, "role"));
        String crRec = engine.recommendForGrantSource(
                node("cr-1", ResourceType.CLUSTER_ROLE, "cr"));

        // All four must be distinct
        List<String> recs = List.of(crbRec, rbRec, roleRec, crRec);
        long distinct = recs.stream().distinct().count();
        assertEquals(4, distinct,
                "Each supported grant type must produce a distinct recommendation");
    }

    @Test
    void nullGrantSourceIsRejected() {
        assertThrows(NullPointerException.class,
                () -> engine.recommendForGrantSource(null));
    }

    /* ------------------------------------------------------------------ */
    /* recommend(Finding) — grant source extracted from path               */
    /* ------------------------------------------------------------------ */

    @Test
    void recommendUsesPenultimateNodeAsGrantSource() {
        GraphNode podNode = node("pod-1", ResourceType.POD, "app-pod");
        GraphNode rbNode = node("rb-1", ResourceType.ROLE_BINDING, "rb");
        GraphNode secretNode = node("s-1", ResourceType.SECRET, "my-secret");

        // path: Pod → RoleBinding → Secret
        Finding finding = fakeFinding(podNode, secretNode,
                List.of(podNode, rbNode, secretNode));

        String rec = engine.recommend(finding);

        // Must use the RoleBinding node's type for the recommendation
        String expectedForRB = engine.recommendForGrantSource(rbNode);
        assertEquals(expectedForRB, rec,
                "recommend() must use the penultimate path node as grant source");
    }

    @Test
    void recommendFallsBackToEntryPointWhenPathHasOnlyOneNode() {
        GraphNode podNode = node("pod-1", ResourceType.POD, "app-pod");
        GraphNode secretNode = node("s-1", ResourceType.SECRET, "my-secret");

        Finding finding = fakeFinding(podNode, secretNode, List.of(podNode));

        String rec = engine.recommend(finding);
        // Should fall back to the entry point
        assertFalse(rec.isBlank());
    }

    @Test
    void nullFindingIsRejected() {
        assertThrows(NullPointerException.class,
                () -> engine.recommend(null));
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                             */
    /* ------------------------------------------------------------------ */

    private static GraphNode node(String id, ResourceType type, String name) {
        return new GraphNode(id, id, type, name, null);
    }

    /**
     * Creates a minimal {@link Finding} without score validation by using
     * a score of 20 (LOW) and matching severity.
     */
    private static Finding fakeFinding(
            GraphNode entry,
            GraphNode target,
            List<GraphNode> path) {

        List<ScoreFactor> factors = List.of(
                new ScoreFactor("TEST", 20, "Test factor")
        );

        return new Finding(
                "test-id",
                "Test Finding",
                "Test description for the finding.",
                entry,
                target,
                path,
                20,
                Severity.LOW,
                factors,
                "Placeholder recommendation."
        );
    }
}
