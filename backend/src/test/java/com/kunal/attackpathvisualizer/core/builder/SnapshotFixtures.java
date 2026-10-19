package com.kunal.attackpathvisualizer.core.builder;

import com.kunal.attackpathvisualizer.common.model.snapshot.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

final class SnapshotFixtures {

    private SnapshotFixtures() {}

    static ClusterSnapshot emptySnapshot(String name) {
        ClusterSnapshot s = new ClusterSnapshot();
        s.setClusterName(name);
        s.setNamespaces(new ArrayList<>());
        s.setNodes(new ArrayList<>());
        s.setPods(new ArrayList<>());
        s.setDeployments(new ArrayList<>());
        s.setReplicaSets(new ArrayList<>());
        s.setServices(new ArrayList<>());
        s.setIngresses(new ArrayList<>());
        s.setServiceAccounts(new ArrayList<>());
        s.setRoles(new ArrayList<>());
        s.setClusterRoles(new ArrayList<>());
        s.setRoleBindings(new ArrayList<>());
        s.setClusterRoleBindings(new ArrayList<>());
        s.setSecrets(new ArrayList<>());
        s.setConfigMaps(new ArrayList<>());
        s.setPersistentVolumes(new ArrayList<>());
        s.setPersistentVolumeClaims(new ArrayList<>());
        return s;
    }

    static <T extends ResourceSnapshot> T with(T r, String uid, String name, String ns) {
        r.setUid(uid);
        r.setName(name);
        r.setNamespace(ns);
        return r;
    }

    static PodSnapshot pod(String uid, String name, String ns, String saName) {
        PodSnapshot p = with(new PodSnapshot(), uid, name, ns);
        p.setServiceAccountName(saName);
        return p;
    }

    static ServiceAccountSnapshot sa(String uid, String name, String ns) {
        return with(new ServiceAccountSnapshot(), uid, name, ns);
    }

    static SecretSnapshot secret(String uid, String name, String ns) {
        SecretSnapshot s = with(new SecretSnapshot(), uid, name, ns);
        s.setSecretType("Opaque");
        return s;
    }

    /** Rule in the core API group. */
    static RbacRuleSnapshot rule(List<String> resources, List<String> verbs, List<String> resourceNames) {
        RbacRuleSnapshot r = new RbacRuleSnapshot();
        r.setApiGroups(List.of(""));
        r.setResources(resources);
        r.setVerbs(verbs);
        r.setResourceNames(resourceNames);
        return r;
    }

    static RoleSnapshot role(String uid, String name, String ns, RbacRuleSnapshot... rules) {
        RoleSnapshot r = with(new RoleSnapshot(), uid, name, ns);
        r.setRules(Arrays.asList(rules));
        return r;
    }

    static ClusterRoleSnapshot clusterRole(String uid, String name, RbacRuleSnapshot... rules) {
        ClusterRoleSnapshot r = with(new ClusterRoleSnapshot(), uid, name, null);
        r.setRules(Arrays.asList(rules));
        return r;
    }

    static RoleBindingSnapshot roleBinding(String uid, String name, String ns,
                                           String roleKind, String roleName, SubjectSnapshot... subjects) {
        RoleBindingSnapshot b = with(new RoleBindingSnapshot(), uid, name, ns);
        b.setRoleKind(roleKind);
        b.setRoleName(roleName);
        b.setSubjects(Arrays.asList(subjects));
        return b;
    }

    static ClusterRoleBindingSnapshot clusterRoleBinding(String uid, String name,
                                                         String clusterRoleName, SubjectSnapshot... subjects) {
        ClusterRoleBindingSnapshot b = with(new ClusterRoleBindingSnapshot(), uid, name, null);
        b.setClusterRoleName(clusterRoleName);
        b.setSubjects(Arrays.asList(subjects));
        return b;
    }

    static SubjectSnapshot saSubject(String name, String ns) {
        return SubjectSnapshot.of("ServiceAccount", name, ns);
    }
}