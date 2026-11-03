package com.kunal.attackpathvisualizer.security;

import com.kunal.attackpathvisualizer.core.model.Cluster;
import com.kunal.attackpathvisualizer.core.model.KubernetesResource;
import com.kunal.attackpathvisualizer.core.model.Pod;
import com.kunal.attackpathvisualizer.core.model.RbacRule;
import com.kunal.attackpathvisualizer.core.model.RbacSubject;
import com.kunal.attackpathvisualizer.core.model.Role;
import com.kunal.attackpathvisualizer.core.model.RoleBinding;
import com.kunal.attackpathvisualizer.core.model.Secret;
import com.kunal.attackpathvisualizer.core.model.ServiceAccount;
import com.kunal.attackpathvisualizer.core.pipeline.ClusterGraphPipeline;
import com.kunal.attackpathvisualizer.core.relation.RelationshipType;
import com.kunal.attackpathvisualizer.core.relation.ResourceRelationship;
import com.kunal.attackpathvisualizer.graph.AttackGraph;
import com.kunal.attackpathvisualizer.graph.GraphBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Regression tests: when a RoleBinding is the grant source and references a
 * Role, the Role must be resolved within the binding's own namespace.
 *
 * The graph is hand-built (RoleBinding -> Secret CAN_ACCESS) because the
 * current ClusterRelationshipBuilder emits that edge only for ClusterRole
 * references.
 */
class AttackPathAnalyzerNamespaceLookupTest {

    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    private AttackPathAnalyzer analyzer;

    @BeforeEach
    void setUp() {
        analyzer = new AttackPathAnalyzer(
                new SecretSensitivityClassifier(), new RiskScorer());
    }

    private static Role role(String uid, String ns, List<RbacRule> rules) {
        return new Role(uid, "reader", ns, Map.of(), Map.of(), NOW, rules);
    }

    private static RbacRule explicitRule() {
        return new RbacRule(List.of(""), List.of("secrets"), List.of("get"), List.of());
    }

    private static RbacRule wildcardRule() {
        return new RbacRule(List.of("*"), List.of("*"), List.of("*"), List.of());
    }

    private static ResourceRelationship rel(KubernetesResource s, KubernetesResource t,
                                            RelationshipType type) {
        return new ResourceRelationship(s, t, type);
    }

    private int wildcardPoints(Cluster cluster) {
        AttackGraph graph = new GraphBuilder().build(cluster);
        List<Finding> findings = analyzer.analyze(
                new ClusterGraphPipeline.PipelineResult(null, cluster, graph));

        assertEquals(1, findings.size());
        return findings.get(0).scoreFactors().stream()
                .filter(f -> "WILDCARD_PERMISSION".equals(f.name()))
                .mapToInt(ScoreFactor::points)
                .sum();
    }

    /** Pod -> SA -> RoleBinding(ns a, Role "reader") -> Secret, built by hand. */
    private Cluster clusterWithBindingInNamespaceA(Role... roles) {
        Pod pod = new Pod("pod", "web", "a", Map.of(), Map.of(), NOW, "sa");
        ServiceAccount sa = new ServiceAccount("sa", "sa", "a", Map.of(), Map.of(), NOW);
        RoleBinding rb = new RoleBinding("rb", "rb", "a", Map.of(), Map.of(), NOW,
                "reader", "Role", List.of(new RbacSubject("ServiceAccount", "sa", "a")));
        Secret secret = new Secret("sec", "data", "a", Map.of(), Map.of(), NOW, "Opaque");

        Cluster cluster = new Cluster("test");
        // Other-namespace Roles are added first so a name-only lookup
        // (findFirst over insertion order) would pick them.
        for (Role r : roles) {
            cluster.addResource(r);
        }
        cluster.addResource(pod);
        cluster.addResource(sa);
        cluster.addResource(rb);
        cluster.addResource(secret);

        cluster.addRelationship(rel(pod, sa, RelationshipType.USES));
        cluster.addRelationship(rel(sa, rb, RelationshipType.HAS_BINDING));
        cluster.addRelationship(rel(rb, secret, RelationshipType.CAN_ACCESS));
        return cluster;
    }

    @Test
    void sameNamedRoleInOtherNamespaceDoesNotInfluenceWildcardScore() {
        Role otherNamespaceWildcard = role("role-b", "b", List.of(wildcardRule()));
        Role ownNamespaceExplicit = role("role-a", "a", List.of(explicitRule()));

        Cluster cluster = clusterWithBindingInNamespaceA(
                otherNamespaceWildcard, ownNamespaceExplicit);

        // Own-namespace Role has explicit rules -> 0. A name-only lookup
        // would have picked namespace b's fully wildcarded Role (25).
        assertEquals(0, wildcardPoints(cluster));
    }

    @Test
    void roleOnlyInOtherNamespaceIsNotResolved() {
        Role otherNamespaceWildcard = role("role-b", "b", List.of(wildcardRule()));

        Cluster cluster = clusterWithBindingInNamespaceA(otherNamespaceWildcard);

        // No "reader" Role in namespace a -> rules unresolved -> 0.
        assertEquals(0, wildcardPoints(cluster));
    }

    @Test
    void roleInSameNamespaceIsStillResolved() {
        Role ownNamespaceWildcard = role("role-a", "a", List.of(wildcardRule()));
        Role otherNamespaceExplicit = role("role-b", "b", List.of(explicitRule()));

        Cluster cluster = clusterWithBindingInNamespaceA(
                otherNamespaceExplicit, ownNamespaceWildcard);

        // Positive control: the same-namespace Role is found and scores 25.
        assertEquals(25, wildcardPoints(cluster));
    }
}