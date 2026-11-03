package com.kunal.attackpathvisualizer.security;

import com.kunal.attackpathvisualizer.core.enums.ResourceType;
import com.kunal.attackpathvisualizer.core.model.Cluster;
import com.kunal.attackpathvisualizer.core.model.ClusterRole;
import com.kunal.attackpathvisualizer.core.model.ClusterRoleBinding;
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
import com.kunal.attackpathvisualizer.graph.GraphEdge;
import com.kunal.attackpathvisualizer.graph.GraphNode;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link AttackPathAnalyzer}.
 *
 * <p>Each test builds a minimal {@link Cluster} + {@link AttackGraph} that is
 * representative of a specific security scenario, then asserts properties of
 * the resulting {@link Finding}s.
 *
 * <p>These tests do NOT start a Spring context; all dependencies are
 * constructed directly.
 */
class AttackPathAnalyzerTest {

    private AttackPathAnalyzer analyzer;

    /* ------------------------------------------------------------------ */
    /* Fixtures                                                             */
    /* ------------------------------------------------------------------ */

    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    @BeforeEach
    void setUp() {
        analyzer = new AttackPathAnalyzer(
                new SecretSensitivityClassifier(),
                new RiskScorer()
        );
    }

    /* ------------------------------------------------------------------ */
    /* Scenario: no path → no findings                                     */
    /* ------------------------------------------------------------------ */

    @Test
    void isolatedGraphProducesNoFindings() {
        Cluster cluster = new Cluster("test");
        AttackGraph graph = new AttackGraph();

        GraphNode podNode = node("pod-1", ResourceType.POD, "my-pod", "default");
        GraphNode secretNode = node("secret-1", ResourceType.SECRET, "my-secret", "default");

        graph.addNode(podNode);
        graph.addNode(secretNode);

        // No edges → no reachable secrets.

        List<Finding> findings = analyzer.analyze(result(cluster, graph));

        assertTrue(findings.isEmpty(), "Isolated graph must produce no findings");
    }

    /* ------------------------------------------------------------------ */
    /* Scenario: Pod → ServiceAccount → RoleBinding → Role → Secret       */
    /* (RoleBinding referencing a Role)                                    */
    /* ------------------------------------------------------------------ */

    @Test
    void roleBindingToRoleProducesOneFindings() {
        String ns = "default";

        Pod pod = pod("pod-uid", "app-pod", ns, "app-sa");
        ServiceAccount sa = sa("sa-uid", "app-sa", ns);
        Role role = role("role-uid", "secret-reader", ns,
                List.of(secretRule(List.of("get"), List.of())));
        RoleBinding rb = roleBinding("rb-uid", "rb", ns, "secret-reader", "Role",
                List.of(new RbacSubject("ServiceAccount", "app-sa", ns)));
        Secret secret = secret("secret-uid", "my-secret", ns, "Opaque");

        Cluster cluster = new Cluster("test");
        cluster.addResource(pod);
        cluster.addResource(sa);
        cluster.addResource(role);
        cluster.addResource(rb);
        cluster.addResource(secret);

        cluster.addRelationship(rel(pod, sa, RelationshipType.USES));
        cluster.addRelationship(rel(sa, rb, RelationshipType.HAS_BINDING));
        cluster.addRelationship(rel(rb, role, RelationshipType.GRANTS));
        cluster.addRelationship(rel(role, secret, RelationshipType.CAN_ACCESS));

        AttackGraph graph = buildGraph(cluster);

        List<Finding> findings = analyzer.analyze(result(cluster, graph));

        assertEquals(1, findings.size(), "Exactly one finding expected");

        Finding f = findings.get(0);
        assertEquals("app-pod", f.entryPoint().getName());
        assertEquals("my-secret", f.target().getName());
        assertFalse(f.attackPath().isEmpty());
        assertEquals("my-secret",
                f.attackPath().get(f.attackPath().size() - 1).getName(),
                "Last node in path must be the Secret");
        assertEquals("app-pod",
                f.attackPath().get(0).getName(),
                "First node in path must be the Pod");
        assertTrue(f.riskScore() >= 0 && f.riskScore() <= 100);
        assertNotNull(f.severity());
        assertEquals(Severity.of(f.riskScore()), f.severity(),
                "Severity must match risk score");
    }

    /* ------------------------------------------------------------------ */
    /* Scenario: RoleBinding referencing a ClusterRole                     */
    /* ------------------------------------------------------------------ */

    @Test
    void roleBindingReferencingClusterRoleIsNamespaceScoped() {
        String ns = "default";

        Pod pod = pod("pod-uid", "app-pod", ns, "app-sa");
        ServiceAccount sa = sa("sa-uid", "app-sa", ns);
        ClusterRole cr = clusterRole("cr-uid", "secret-reader",
                List.of(secretRule(List.of("get"), List.of())));
        RoleBinding rb = roleBinding("rb-uid", "rb", ns, "secret-reader", "ClusterRole",
                List.of(new RbacSubject("ServiceAccount", "app-sa", ns)));
        Secret secret = secret("secret-uid", "my-secret", ns, "Opaque");

        Cluster cluster = new Cluster("test");
        cluster.addResource(pod);
        cluster.addResource(sa);
        cluster.addResource(cr);
        cluster.addResource(rb);
        cluster.addResource(secret);

        cluster.addRelationship(rel(pod, sa, RelationshipType.USES));
        cluster.addRelationship(rel(sa, rb, RelationshipType.HAS_BINDING));
        cluster.addRelationship(rel(rb, cr, RelationshipType.GRANTS));
        // Access edge comes from the RoleBinding, not the ClusterRole itself,
        // because the binding limits the scope to its namespace.
        cluster.addRelationship(rel(rb, secret, RelationshipType.CAN_ACCESS));

        AttackGraph graph = buildGraph(cluster);

        List<Finding> findings = analyzer.analyze(result(cluster, graph));

        assertEquals(1, findings.size());

        Finding f = findings.get(0);

        // The grant source in the path must be the RoleBinding, not the ClusterRole.
        GraphNode grantSource = f.attackPath().get(f.attackPath().size() - 2);
        assertEquals(ResourceType.ROLE_BINDING, grantSource.getResourceType(),
                "Grant source must be the RoleBinding for namespace-scoped access");

        // PERMISSION_SCOPE score must be 15 (RoleBinding).
        int scopePoints = f.scoreFactors().stream()
                .filter(sf -> "PERMISSION_SCOPE".equals(sf.name()))
                .mapToInt(ScoreFactor::points)
                .sum();
        assertEquals(15, scopePoints,
                "RoleBinding must contribute PERMISSION_SCOPE=15");
    }

    /* ------------------------------------------------------------------ */
    /* Scenario: ClusterRoleBinding referencing a ClusterRole              */
    /* ------------------------------------------------------------------ */

    @Test
    void clusterRoleBindingProducesHighPermissionScopeScore() {
        String ns = "production";

        Pod pod = pod("pod-uid", "app-pod", ns, "app-sa");
        ServiceAccount sa = sa("sa-uid", "app-sa", ns);
        ClusterRole cr = clusterRole("cr-uid", "cluster-admin",
                List.of(wildcardRule()));
        ClusterRoleBinding crb = clusterRoleBinding("crb-uid", "crb", "cluster-admin",
                List.of(new RbacSubject("ServiceAccount", "app-sa", ns)));
        Secret secret = secret("secret-uid", "my-secret", ns, "Opaque");

        Cluster cluster = new Cluster("test");
        cluster.addResource(pod);
        cluster.addResource(sa);
        cluster.addResource(cr);
        cluster.addResource(crb);
        cluster.addResource(secret);

        cluster.addRelationship(rel(pod, sa, RelationshipType.USES));
        cluster.addRelationship(rel(sa, crb, RelationshipType.HAS_BINDING));
        cluster.addRelationship(rel(crb, cr, RelationshipType.GRANTS));
        cluster.addRelationship(rel(crb, secret, RelationshipType.CAN_ACCESS));

        AttackGraph graph = buildGraph(cluster);

        List<Finding> findings = analyzer.analyze(result(cluster, graph));

        assertEquals(1, findings.size());

        Finding f = findings.get(0);

        int scopePoints = f.scoreFactors().stream()
                .filter(sf -> "PERMISSION_SCOPE".equals(sf.name()))
                .mapToInt(ScoreFactor::points)
                .sum();
        assertEquals(30, scopePoints,
                "ClusterRoleBinding must contribute PERMISSION_SCOPE=30");

        // Wildcard rule → WILDCARD_PERMISSION = 25.
        int wildcardPoints = f.scoreFactors().stream()
                .filter(sf -> "WILDCARD_PERMISSION".equals(sf.name()))
                .mapToInt(ScoreFactor::points)
                .sum();
        assertEquals(25, wildcardPoints,
                "Fully wildcarded rules must contribute WILDCARD_PERMISSION=25");
    }

    /* ------------------------------------------------------------------ */
    /* Scenario: wildcard verbs only                                       */
    /* ------------------------------------------------------------------ */

    @Test
    void partialWildcardInVerbsProducesTenPoints() {
        String ns = "default";

        Pod pod = pod("pod-uid", "app-pod", ns, "app-sa");
        ServiceAccount sa = sa("sa-uid", "app-sa", ns);
        // apiGroups and resources are explicit, but verbs is "*"
        Role role = role("role-uid", "secret-reader", ns,
                List.of(new RbacRule(List.of(""), List.of("secrets"), List.of("*"), List.of())));
        RoleBinding rb = roleBinding("rb-uid", "rb", ns, "secret-reader", "Role",
                List.of(new RbacSubject("ServiceAccount", "app-sa", ns)));
        Secret secret = secret("secret-uid", "my-secret", ns, "Opaque");

        Cluster cluster = new Cluster("test");
        cluster.addResource(pod);
        cluster.addResource(sa);
        cluster.addResource(role);
        cluster.addResource(rb);
        cluster.addResource(secret);

        cluster.addRelationship(rel(pod, sa, RelationshipType.USES));
        cluster.addRelationship(rel(sa, rb, RelationshipType.HAS_BINDING));
        cluster.addRelationship(rel(rb, role, RelationshipType.GRANTS));
        cluster.addRelationship(rel(role, secret, RelationshipType.CAN_ACCESS));

        AttackGraph graph = buildGraph(cluster);

        List<Finding> findings = analyzer.analyze(result(cluster, graph));

        assertEquals(1, findings.size());

        int wildcardPoints = findings.get(0).scoreFactors().stream()
                .filter(sf -> "WILDCARD_PERMISSION".equals(sf.name()))
                .mapToInt(ScoreFactor::points)
                .sum();

        assertEquals(10, wildcardPoints,
                "Partial wildcard (verb=*) must contribute WILDCARD_PERMISSION=10");
    }

    /* ------------------------------------------------------------------ */
    /* Scenario: multiple Pods → same Secret                               */
    /* ------------------------------------------------------------------ */

    @Test
    void multiplePodsAccessingSameSecretProduceSeparateFindings() {
        String ns = "default";

        Pod pod1 = pod("pod-uid-1", "pod-1", ns, "sa-1");
        Pod pod2 = pod("pod-uid-2", "pod-2", ns, "sa-2");
        ServiceAccount sa1 = sa("sa-uid-1", "sa-1", ns);
        ServiceAccount sa2 = sa("sa-uid-2", "sa-2", ns);
        Role role = role("role-uid", "secret-reader", ns,
                List.of(secretRule(List.of("get"), List.of())));
        RoleBinding rb1 = roleBinding("rb-uid-1", "rb-1", ns, "secret-reader", "Role",
                List.of(new RbacSubject("ServiceAccount", "sa-1", ns)));
        RoleBinding rb2 = roleBinding("rb-uid-2", "rb-2", ns, "secret-reader", "Role",
                List.of(new RbacSubject("ServiceAccount", "sa-2", ns)));
        Secret secret = secret("secret-uid", "shared-secret", ns, "Opaque");

        Cluster cluster = new Cluster("test");
        cluster.addResource(pod1);
        cluster.addResource(pod2);
        cluster.addResource(sa1);
        cluster.addResource(sa2);
        cluster.addResource(role);
        cluster.addResource(rb1);
        cluster.addResource(rb2);
        cluster.addResource(secret);

        cluster.addRelationship(rel(pod1, sa1, RelationshipType.USES));
        cluster.addRelationship(rel(sa1, rb1, RelationshipType.HAS_BINDING));
        cluster.addRelationship(rel(rb1, role, RelationshipType.GRANTS));
        cluster.addRelationship(rel(role, secret, RelationshipType.CAN_ACCESS));

        cluster.addRelationship(rel(pod2, sa2, RelationshipType.USES));
        cluster.addRelationship(rel(sa2, rb2, RelationshipType.HAS_BINDING));
        cluster.addRelationship(rel(rb2, role, RelationshipType.GRANTS));
        // The same CAN_ACCESS edge is shared (graph deduplicates).

        AttackGraph graph = buildGraph(cluster);

        List<Finding> findings = analyzer.analyze(result(cluster, graph));

        assertEquals(2, findings.size(),
                "Each Pod must produce a separate finding");

        Set<String> entryPoints = findings.stream()
                .map(f -> f.entryPoint().getName())
                .collect(Collectors.toSet());
        assertTrue(entryPoints.contains("pod-1"));
        assertTrue(entryPoints.contains("pod-2"));
    }

    /* ------------------------------------------------------------------ */
    /* Scenario: multiple grants to the same Secret                        */
    /* ------------------------------------------------------------------ */

    @Test
    void multipleGrantsToSameSecretProduceSeparateFindings() {
        String ns = "default";

        Pod pod = pod("pod-uid", "app-pod", ns, "app-sa");
        ServiceAccount sa = sa("sa-uid", "app-sa", ns);
        Role role = role("role-uid", "secret-reader", ns,
                List.of(secretRule(List.of("get"), List.of())));
        ClusterRole cr = clusterRole("cr-uid", "cluster-admin",
                List.of(wildcardRule()));
        RoleBinding rb = roleBinding("rb-uid", "rb", ns, "secret-reader", "Role",
                List.of(new RbacSubject("ServiceAccount", "app-sa", ns)));
        ClusterRoleBinding crb = clusterRoleBinding("crb-uid", "crb", "cluster-admin",
                List.of(new RbacSubject("ServiceAccount", "app-sa", ns)));
        Secret secret = secret("secret-uid", "my-secret", ns, "Opaque");

        Cluster cluster = new Cluster("test");
        cluster.addResource(pod);
        cluster.addResource(sa);
        cluster.addResource(role);
        cluster.addResource(cr);
        cluster.addResource(rb);
        cluster.addResource(crb);
        cluster.addResource(secret);

        // Grant via RoleBinding → Role
        cluster.addRelationship(rel(pod, sa, RelationshipType.USES));
        cluster.addRelationship(rel(sa, rb, RelationshipType.HAS_BINDING));
        cluster.addRelationship(rel(rb, role, RelationshipType.GRANTS));
        cluster.addRelationship(rel(role, secret, RelationshipType.CAN_ACCESS));

        // Grant via ClusterRoleBinding → ClusterRole (separate HAS_BINDING)
        cluster.addRelationship(rel(sa, crb, RelationshipType.HAS_BINDING));
        cluster.addRelationship(rel(crb, cr, RelationshipType.GRANTS));
        cluster.addRelationship(rel(crb, secret, RelationshipType.CAN_ACCESS));

        AttackGraph graph = buildGraph(cluster);

        List<Finding> findings = analyzer.analyze(result(cluster, graph));

        assertEquals(2, findings.size(),
                "Two separate grants must produce two distinct findings");

        Set<String> grantSourceTypes = findings.stream()
                .map(f -> f.attackPath().get(f.attackPath().size() - 2).getResourceType().name())
                .collect(Collectors.toSet());

        assertTrue(grantSourceTypes.contains("ROLE"),
                "One finding must be rooted at the Role");
        assertTrue(grantSourceTypes.contains("CLUSTER_ROLE_BINDING"),
                "One finding must be rooted at the ClusterRoleBinding");
    }

    /* ------------------------------------------------------------------ */
    /* Scenario: resource-name restriction (specific Secret name)          */
    /* ------------------------------------------------------------------ */

    @Test
    void resourceNameRestrictionLimitsAccessToNamedSecret() {
        String ns = "default";

        Pod pod = pod("pod-uid", "app-pod", ns, "app-sa");
        ServiceAccount sa = sa("sa-uid", "app-sa", ns);
        // Role grants access only to "restricted-secret"
        Role role = role("role-uid", "named-reader", ns,
                List.of(secretRule(List.of("get"), List.of("restricted-secret"))));
        RoleBinding rb = roleBinding("rb-uid", "rb", ns, "named-reader", "Role",
                List.of(new RbacSubject("ServiceAccount", "app-sa", ns)));
        Secret restricted = secret("s-uid-1", "restricted-secret", ns, "Opaque");
        Secret other = secret("s-uid-2", "other-secret", ns, "Opaque");

        Cluster cluster = new Cluster("test");
        cluster.addResource(pod);
        cluster.addResource(sa);
        cluster.addResource(role);
        cluster.addResource(rb);
        cluster.addResource(restricted);
        cluster.addResource(other);

        cluster.addRelationship(rel(pod, sa, RelationshipType.USES));
        cluster.addRelationship(rel(sa, rb, RelationshipType.HAS_BINDING));
        cluster.addRelationship(rel(rb, role, RelationshipType.GRANTS));
        // Only the restricted secret is reachable via CAN_ACCESS.
        cluster.addRelationship(rel(role, restricted, RelationshipType.CAN_ACCESS));

        AttackGraph graph = buildGraph(cluster);

        List<Finding> findings = analyzer.analyze(result(cluster, graph));

        assertEquals(1, findings.size(),
                "Only the named Secret must be reachable");
        assertEquals("restricted-secret", findings.get(0).target().getName());
    }

    /* ------------------------------------------------------------------ */
    /* Scenario: wildcard rule produces CRITICAL severity                  */
    /* ------------------------------------------------------------------ */

    @Test
    void fullyWildcardedClusterRoleBindingCanProduceCriticalSeverity() {
        String ns = "production";

        Pod pod = pod("pod-uid", "app-pod", ns, "app-sa");
        ServiceAccount sa = sa("sa-uid", "app-sa", ns);
        ClusterRole cr = clusterRole("cr-uid", "cluster-admin",
                List.of(wildcardRule()));
        ClusterRoleBinding crb = clusterRoleBinding("crb-uid", "crb", "cluster-admin",
                List.of(new RbacSubject("ServiceAccount", "app-sa", ns)));
        // Highly sensitive secret: TLS type in kube-system, sensitive label, "tls" in name
        Secret secret = new Secret(
                "secret-uid", "prod-tls", "kube-system",
                Map.of("sensitive", "true"),
                Map.of(),
                NOW,
                "kubernetes.io/tls"
        );

        Cluster cluster = new Cluster("test");
        cluster.addResource(pod);
        cluster.addResource(sa);
        cluster.addResource(cr);
        cluster.addResource(crb);
        cluster.addResource(secret);

        cluster.addRelationship(rel(pod, sa, RelationshipType.USES));
        cluster.addRelationship(rel(sa, crb, RelationshipType.HAS_BINDING));
        cluster.addRelationship(rel(crb, cr, RelationshipType.GRANTS));
        cluster.addRelationship(rel(crb, secret, RelationshipType.CAN_ACCESS));

        AttackGraph graph = buildGraph(cluster);

        List<Finding> findings = analyzer.analyze(result(cluster, graph));

        assertEquals(1, findings.size());

        Finding f = findings.get(0);

        // sensitivity=40 (capped), scope=30, wildcard=25, path=5 → 100 → CRITICAL
        assertEquals(Severity.CRITICAL, f.severity(),
                "Fully wildcarded CRB with max-sensitivity secret must be CRITICAL");
        assertTrue(f.riskScore() >= 75,
                "Risk score must be at least 75 for CRITICAL");
    }

    /* ------------------------------------------------------------------ */
    /* Scenario: no valid path → no finding                                */
    /* ------------------------------------------------------------------ */

    @Test
    void podCannotReachDisconnectedSecret() {
        Cluster cluster = new Cluster("test");
        AttackGraph graph = new AttackGraph();

        GraphNode podNode = node("pod-1", ResourceType.POD, "my-pod", "default");
        GraphNode roleNode = node("role-1", ResourceType.ROLE, "my-role", "default");
        GraphNode secretNode = node("secret-1", ResourceType.SECRET, "my-secret", "default");

        // Add CAN_ACCESS edge from role → secret, but no path from pod to role
        graph.addEdge(new GraphEdge(roleNode, secretNode, RelationshipType.CAN_ACCESS, 1));
        graph.addNode(podNode);

        // Pod is not connected to role
        List<Finding> findings = analyzer.analyze(result(cluster, graph));

        assertTrue(findings.isEmpty(),
                "A disconnected Pod must produce no findings");
    }

    /* ------------------------------------------------------------------ */
    /* Scenario: null inputs rejected                                      */
    /* ------------------------------------------------------------------ */

    @Test
    void nullPipelineResultIsRejected() {
        assertThrows(NullPointerException.class,
                () -> analyzer.analyze(null));
    }

    /* ------------------------------------------------------------------ */
    /* Scenario: score factors are all explainable                         */
    /* ------------------------------------------------------------------ */

    @Test
    void allScoreFactorsHaveNonBlankNames() {
        String ns = "default";

        Pod pod = pod("pod-uid", "app-pod", ns, "app-sa");
        ServiceAccount sa = sa("sa-uid", "app-sa", ns);
        Role role = role("role-uid", "secret-reader", ns,
                List.of(secretRule(List.of("get"), List.of())));
        RoleBinding rb = roleBinding("rb-uid", "rb", ns, "secret-reader", "Role",
                List.of(new RbacSubject("ServiceAccount", "app-sa", ns)));
        Secret secret = secret("secret-uid", "my-secret", ns, "Opaque");

        Cluster cluster = new Cluster("test");
        cluster.addResource(pod);
        cluster.addResource(sa);
        cluster.addResource(role);
        cluster.addResource(rb);
        cluster.addResource(secret);

        cluster.addRelationship(rel(pod, sa, RelationshipType.USES));
        cluster.addRelationship(rel(sa, rb, RelationshipType.HAS_BINDING));
        cluster.addRelationship(rel(rb, role, RelationshipType.GRANTS));
        cluster.addRelationship(rel(role, secret, RelationshipType.CAN_ACCESS));

        AttackGraph graph = buildGraph(cluster);

        List<Finding> findings = analyzer.analyze(result(cluster, graph));

        assertEquals(1, findings.size());

        for (ScoreFactor sf : findings.get(0).scoreFactors()) {
            assertFalse(sf.name().isBlank(), "Score factor name must not be blank");
            assertFalse(sf.reason().isBlank(), "Score factor reason must not be blank");
            assertTrue(sf.points() >= 0, "Score factor points must be non-negative");
        }
    }

    /* ------------------------------------------------------------------ */
    /* Scenario: attack path always starts with Pod and ends with Secret   */
    /* ------------------------------------------------------------------ */

    @Test
    void attackPathStartsWithPodAndEndsWithSecret() {
        String ns = "default";

        Pod pod = pod("pod-uid", "app-pod", ns, "app-sa");
        ServiceAccount sa = sa("sa-uid", "app-sa", ns);
        Role role = role("role-uid", "reader", ns,
                List.of(secretRule(List.of("get"), List.of())));
        RoleBinding rb = roleBinding("rb-uid", "rb", ns, "reader", "Role",
                List.of(new RbacSubject("ServiceAccount", "app-sa", ns)));
        Secret secret = secret("secret-uid", "vault-secret", ns, "Opaque");

        Cluster cluster = new Cluster("test");
        cluster.addResource(pod);
        cluster.addResource(sa);
        cluster.addResource(role);
        cluster.addResource(rb);
        cluster.addResource(secret);

        cluster.addRelationship(rel(pod, sa, RelationshipType.USES));
        cluster.addRelationship(rel(sa, rb, RelationshipType.HAS_BINDING));
        cluster.addRelationship(rel(rb, role, RelationshipType.GRANTS));
        cluster.addRelationship(rel(role, secret, RelationshipType.CAN_ACCESS));

        AttackGraph graph = buildGraph(cluster);

        List<Finding> findings = analyzer.analyze(result(cluster, graph));

        assertEquals(1, findings.size());

        List<GraphNode> path = findings.get(0).attackPath();

        assertTrue(path.size() >= 2,
                "Attack path must contain at least two nodes");
        assertEquals(ResourceType.POD, path.get(0).getResourceType(),
                "First node must be the Pod");
        assertEquals(ResourceType.SECRET, path.get(path.size() - 1).getResourceType(),
                "Last node must be the Secret");
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                              */
    /* ------------------------------------------------------------------ */

    private static GraphNode node(String id, ResourceType type, String name, String ns) {
        return new GraphNode(id, id, type, name, ns);
    }

    private static Pod pod(String uid, String name, String ns, String saName) {
        return new Pod(uid, name, ns, Map.of(), Map.of(), NOW, saName);
    }

    private static ServiceAccount sa(String uid, String name, String ns) {
        return new ServiceAccount(uid, name, ns, Map.of(), Map.of(), NOW);
    }

    private static Role role(String uid, String name, String ns, List<RbacRule> rules) {
        return new Role(uid, name, ns, Map.of(), Map.of(), NOW, rules);
    }

    private static ClusterRole clusterRole(String uid, String name, List<RbacRule> rules) {
        return new ClusterRole(uid, name, Map.of(), Map.of(), NOW, rules);
    }

    private static RoleBinding roleBinding(String uid, String name, String ns,
                                           String roleName, String roleKind,
                                           List<RbacSubject> subjects) {
        return new RoleBinding(uid, name, ns, Map.of(), Map.of(), NOW,
                roleName, roleKind, subjects);
    }

    private static ClusterRoleBinding clusterRoleBinding(String uid, String name,
                                                          String crName,
                                                          List<RbacSubject> subjects) {
        return new ClusterRoleBinding(uid, name, Map.of(), Map.of(), NOW,
                crName, subjects);
    }

    private static Secret secret(String uid, String name, String ns, String type) {
        return new Secret(uid, name, ns, Map.of(), Map.of(), NOW, type);
    }

    private static RbacRule secretRule(List<String> verbs, List<String> resourceNames) {
        return new RbacRule(List.of(""), List.of("secrets"), verbs, resourceNames);
    }

    private static RbacRule wildcardRule() {
        return new RbacRule(List.of("*"), List.of("*"), List.of("*"), List.of());
    }

    private static ResourceRelationship rel(
            com.kunal.attackpathvisualizer.core.model.KubernetesResource src,
            com.kunal.attackpathvisualizer.core.model.KubernetesResource tgt,
            RelationshipType type) {
        return new ResourceRelationship(src, tgt, type);
    }

    /**
     * Builds an {@link AttackGraph} from the cluster's relationships.
     * Each resource becomes a node; each relationship becomes an edge.
     */
    private static AttackGraph buildGraph(Cluster cluster) {
        com.kunal.attackpathvisualizer.graph.GraphBuilder builder =
                new com.kunal.attackpathvisualizer.graph.GraphBuilder();
        return builder.build(cluster);
    }

    private static ClusterGraphPipeline.PipelineResult result(
            Cluster cluster, AttackGraph graph) {
        return new ClusterGraphPipeline.PipelineResult(null, cluster, graph);
    }
}
