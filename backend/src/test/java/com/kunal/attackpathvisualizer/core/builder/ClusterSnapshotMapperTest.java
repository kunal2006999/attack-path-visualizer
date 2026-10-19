package com.kunal.attackpathvisualizer.core.builder;

import com.kunal.attackpathvisualizer.common.model.snapshot.ClusterSnapshot;
import com.kunal.attackpathvisualizer.core.model.Cluster;
import com.kunal.attackpathvisualizer.core.relation.RelationshipType;
import org.junit.jupiter.api.Test;

import java.util.List;

import static com.kunal.attackpathvisualizer.core.builder.SnapshotFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

class ClusterSnapshotMapperTest {

    private final ClusterSnapshotMapper mapper = new ClusterSnapshotMapper();

    private static boolean hasRel(Cluster c, String srcUid, String tgtUid, RelationshipType type) {
        return c.getRelationships().stream().anyMatch(r ->
                r.getSource().getUid().equals(srcUid)
                        && r.getTarget().getUid().equals(tgtUid)
                        && r.getType() == type);
    }

    private static long count(Cluster c, RelationshipType type) {
        return c.getRelationships().stream().filter(r -> r.getType() == type).count();
    }

    @Test
    void mapsEmptySnapshot() {
        Cluster cluster = mapper.map(emptySnapshot("empty"));
        assertEquals("empty", cluster.getName());
        assertTrue(cluster.getResources().isEmpty());
        assertTrue(cluster.getRelationships().isEmpty());
    }

    @Test
    void mapsSnapshotWithNullLists() {
        ClusterSnapshot s = new ClusterSnapshot();
        s.setClusterName("nulls");
        Cluster cluster = mapper.map(s);
        assertTrue(cluster.getResources().isEmpty());
    }

    @Test
    void rejectsNullSnapshot() {
        assertThrows(IllegalArgumentException.class, () -> mapper.map(null));
    }

    @Test
    void roleWithNullRulesDoesNotThrow() {
        ClusterSnapshot s = emptySnapshot("c");
        var r = role("r1", "r", "a");
        r.setRules(null);
        s.getRoles().add(r);
        assertDoesNotThrow(() -> mapper.map(s));
    }

    @Test
    void podLinksOnlyToServiceAccountInSameNamespace() {
        ClusterSnapshot s = emptySnapshot("c");
        s.getServiceAccounts().add(sa("sa-a", "app-sa", "a"));
        s.getServiceAccounts().add(sa("sa-b", "app-sa", "b"));
        s.getPods().add(pod("pod-a", "web", "a", "app-sa"));

        Cluster c = mapper.map(s);

        assertEquals(1, count(c, RelationshipType.USES));
        assertTrue(hasRel(c, "pod-a", "sa-a", RelationshipType.USES));
    }

    @Test
    void roleBindingToRoleGrantsOnlySecretsInRoleNamespace() {
        ClusterSnapshot s = emptySnapshot("c");
        s.getServiceAccounts().add(sa("sa-a", "app-sa", "a"));
        s.getRoles().add(role("role-a", "reader", "a", rule(List.of("secrets"), List.of("get"), List.of())));
        s.getRoleBindings().add(roleBinding("rb-a", "rb", "a", "Role", "reader", saSubject("app-sa", "a")));
        s.getSecrets().add(secret("sec-a", "s", "a"));
        s.getSecrets().add(secret("sec-b", "s", "b"));

        Cluster c = mapper.map(s);

        assertTrue(hasRel(c, "sa-a", "rb-a", RelationshipType.HAS_BINDING));
        assertTrue(hasRel(c, "rb-a", "role-a", RelationshipType.GRANTS));
        assertTrue(hasRel(c, "role-a", "sec-a", RelationshipType.CAN_ACCESS));
        assertFalse(hasRel(c, "role-a", "sec-b", RelationshipType.CAN_ACCESS));
    }

    @Test
    void roleBindingReferencingClusterRoleIsLimitedToBindingNamespace() {
        ClusterSnapshot s = emptySnapshot("c");
        s.getServiceAccounts().add(sa("sa-a", "app-sa", "a"));
        s.getClusterRoles().add(clusterRole("cr", "secret-reader", rule(List.of("secrets"), List.of("get"), List.of())));
        s.getRoleBindings().add(roleBinding("rb-a", "rb", "a", "ClusterRole", "secret-reader", saSubject("app-sa", "a")));
        s.getSecrets().add(secret("sec-a", "s", "a"));
        s.getSecrets().add(secret("sec-b", "s", "b"));

        Cluster c = mapper.map(s);

        assertTrue(hasRel(c, "rb-a", "cr", RelationshipType.GRANTS));
        assertTrue(hasRel(c, "rb-a", "sec-a", RelationshipType.CAN_ACCESS));
        assertFalse(hasRel(c, "rb-a", "sec-b", RelationshipType.CAN_ACCESS));
        // shared ClusterRole node must not carry scope-specific grants
        assertFalse(hasRel(c, "cr", "sec-a", RelationshipType.CAN_ACCESS));
    }

    @Test
    void clusterRoleBindingUsesSubjectNamespaceNotBindingNamespace() {
        ClusterSnapshot s = emptySnapshot("c");
        s.getServiceAccounts().add(sa("sa-a", "app-sa", "a"));
        s.getServiceAccounts().add(sa("sa-b", "app-sa", "b"));
        s.getClusterRoles().add(clusterRole("cr", "reader", rule(List.of("secrets"), List.of("get"), List.of())));
        s.getClusterRoleBindings().add(clusterRoleBinding("crb", "crb", "reader", saSubject("app-sa", "b")));
        s.getSecrets().add(secret("sec-a", "s", "a"));
        s.getSecrets().add(secret("sec-b", "s", "b"));

        Cluster c = mapper.map(s);

        assertTrue(hasRel(c, "sa-b", "crb", RelationshipType.HAS_BINDING));
        assertFalse(hasRel(c, "sa-a", "crb", RelationshipType.HAS_BINDING));
        // cluster-wide grant reaches secrets in every namespace
        assertTrue(hasRel(c, "crb", "sec-a", RelationshipType.CAN_ACCESS));
        assertTrue(hasRel(c, "crb", "sec-b", RelationshipType.CAN_ACCESS));
    }

    @Test
    void userAndGroupSubjectsAreNotTreatedAsServiceAccounts() {
        ClusterSnapshot s = emptySnapshot("c");
        s.getServiceAccounts().add(sa("sa-a", "alice", "a"));
        s.getClusterRoles().add(clusterRole("cr", "reader", rule(List.of("secrets"), List.of("get"), List.of())));
        s.getClusterRoleBindings().add(clusterRoleBinding("crb", "crb", "reader",
                com.kunal.attackpathvisualizer.common.model.snapshot.SubjectSnapshot.of("User", "alice", null),
                com.kunal.attackpathvisualizer.common.model.snapshot.SubjectSnapshot.of("Group", "alice", null)));

        Cluster c = mapper.map(s);

        assertEquals(0, count(c, RelationshipType.HAS_BINDING));
    }

    @Test
    void wildcardResourceWithOnlyDeleteVerbGrantsNoSecretAccess() {
        ClusterSnapshot s = emptySnapshot("c");
        s.getRoles().add(role("role", "r", "a", rule(List.of("*"), List.of("delete"), List.of())));
        s.getRoleBindings().add(roleBinding("rb", "rb", "a", "Role", "r"));
        s.getSecrets().add(secret("sec", "s", "a"));

        Cluster c = mapper.map(s);

        assertEquals(0, count(c, RelationshipType.CAN_ACCESS));
    }

    @Test
    void ruleOnOtherResourcesGrantsNoSecretAccess() {
        ClusterSnapshot s = emptySnapshot("c");
        s.getRoles().add(role("role", "r", "a", rule(List.of("pods"), List.of("get"), List.of())));
        s.getRoleBindings().add(roleBinding("rb", "rb", "a", "Role", "r"));
        s.getSecrets().add(secret("sec", "s", "a"));

        assertEquals(0, count(mapper.map(s), RelationshipType.CAN_ACCESS));
    }

    @Test
    void resourceNamesRestrictSecretAccess() {
        ClusterSnapshot s = emptySnapshot("c");
        s.getRoles().add(role("role", "r", "a", rule(List.of("secrets"), List.of("get"), List.of("secret-a"))));
        s.getRoleBindings().add(roleBinding("rb", "rb", "a", "Role", "r"));
        s.getSecrets().add(secret("sa", "secret-a", "a"));
        s.getSecrets().add(secret("sb", "secret-b", "a"));

        Cluster c = mapper.map(s);

        assertTrue(hasRel(c, "role", "sa", RelationshipType.CAN_ACCESS));
        assertFalse(hasRel(c, "role", "sb", RelationshipType.CAN_ACCESS));
    }

    @Test
    void unresolvedReferencesProduceNoRelationships() {
        ClusterSnapshot s = emptySnapshot("c");
        s.getPods().add(pod("pod", "p", "a", "missing-sa"));
        s.getRoleBindings().add(roleBinding("rb", "rb", "a", "Role", "missing-role", saSubject("ghost", "a")));
        s.getClusterRoleBindings().add(clusterRoleBinding("crb", "crb", "missing", saSubject("ghost", "a")));

        Cluster c = mapper.map(s);

        assertEquals(3, c.getResources().size());
        assertTrue(c.getRelationships().isEmpty());
    }

    @Test
    void serviceSelectsOnlyMatchingPodsInSameNamespace() {
        ClusterSnapshot s = emptySnapshot("c");
        var matching = pod("p1", "web", "a", null);
        matching.setLabels(java.util.Map.of("app", "web"));
        var otherNs = pod("p2", "web", "b", null);
        otherNs.setLabels(java.util.Map.of("app", "web"));
        var otherLabel = pod("p3", "db", "a", null);
        otherLabel.setLabels(java.util.Map.of("app", "db"));
        s.getPods().addAll(List.of(matching, otherNs, otherLabel));
        var svc = with(new com.kunal.attackpathvisualizer.common.model.snapshot.ServiceSnapshot(), "svc", "web-svc", "a");
        svc.setSelector(java.util.Map.of("app", "web"));
        s.getServices().add(svc);

        Cluster c = mapper.map(s);

        assertEquals(1, count(c, RelationshipType.SELECTS));
        assertTrue(hasRel(c, "svc", "p1", RelationshipType.SELECTS));
    }
}