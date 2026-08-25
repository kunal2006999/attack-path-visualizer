package com.kunal.attackpathvisualizer.common.model.snapshot;

import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for Phase 4.1 snapshot DTOs (Phase 4.2).
 */
class SnapshotDtoTest {

    @Test
    void podSnapshot_canBeInstantiatedAndFieldsRoundTrip() {
        PodSnapshot pod = new PodSnapshot();
        Instant now = Instant.parse("2025-01-15T10:00:00Z");
        pod.setUid("pod-uid-001");
        pod.setName("frontend-pod");
        pod.setNamespace("production");
        pod.setCreationTimestamp(now);
        pod.setServiceAccountName("frontend-sa");
        assertEquals("pod-uid-001", pod.getUid());
        assertEquals("frontend-pod", pod.getName());
        assertEquals("production", pod.getNamespace());
        assertEquals(now, pod.getCreationTimestamp());
        assertEquals("frontend-sa", pod.getServiceAccountName());
    }

    @Test
    void rbacRuleSnapshot_fieldsRoundTrip() {
        RbacRuleSnapshot rule = new RbacRuleSnapshot();
        rule.setApiGroups(Arrays.asList("", "apps"));
        rule.setResources(Arrays.asList("pods", "deployments"));
        rule.setVerbs(Arrays.asList("get", "list", "watch"));
        rule.setResourceNames(Arrays.asList("my-resource"));
        assertEquals(2, rule.getApiGroups().size());
        assertTrue(rule.getApiGroups().contains("apps"));
        assertEquals(2, rule.getResources().size());
        assertEquals(3, rule.getVerbs().size());
        assertEquals(1, rule.getResourceNames().size());
    }

    @Test
    void roleSnapshot_canHoldRbacRuleSnapshots() {
        RbacRuleSnapshot rule1 = new RbacRuleSnapshot();
        rule1.setApiGroups(List.of(""));
        rule1.setResources(List.of("secrets"));
        rule1.setVerbs(List.of("get", "list"));
        rule1.setResourceNames(List.of());
        RbacRuleSnapshot rule2 = new RbacRuleSnapshot();
        rule2.setApiGroups(List.of("apps"));
        rule2.setResources(List.of("deployments"));
        rule2.setVerbs(List.of("create", "delete"));
        rule2.setResourceNames(List.of());
        RoleSnapshot role = new RoleSnapshot();
        role.setUid("role-uid-001");
        role.setName("read-secrets");
        role.setNamespace("default");
        role.setRules(Arrays.asList(rule1, rule2));
        assertEquals("role-uid-001", role.getUid());
        assertNotNull(role.getRules());
        assertEquals(2, role.getRules().size());
        assertTrue(role.getRules().get(0).getResources().contains("secrets"));
    }

    @Test
    void clusterSnapshot_canHoldTypedResourceLists() {
        ClusterSnapshot cluster = new ClusterSnapshot();
        cluster.setClusterName("test-cluster");
        NamespaceSnapshot ns = new NamespaceSnapshot();
        ns.setName("production");
        cluster.setNamespaces(List.of(ns));
        NodeSnapshot node = new NodeSnapshot();
        node.setName("worker-1");
        cluster.setNodes(List.of(node));
        PodSnapshot pod = new PodSnapshot();
        pod.setName("web-pod");
        pod.setServiceAccountName("web-sa");
        cluster.setPods(List.of(pod));
        Map<String, String> sel = new HashMap<>();
        sel.put("app", "web");
        ServiceSnapshot svc = new ServiceSnapshot();
        svc.setName("web-service");
        svc.setSelector(sel);
        cluster.setServices(List.of(svc));
        DeploymentSnapshot dep = new DeploymentSnapshot();
        dep.setName("web-deployment");
        dep.setReplicas(3);
        dep.setSelector(sel);
        cluster.setDeployments(List.of(dep));
        SecretSnapshot secret = new SecretSnapshot();
        secret.setName("db-password");
        secret.setSecretType("Opaque");
        cluster.setSecrets(List.of(secret));
        PersistentVolumeSnapshot pv = new PersistentVolumeSnapshot();
        pv.setName("data-pv");
        pv.setStorageClassName("standard");
        cluster.setPersistentVolumes(List.of(pv));
        PersistentVolumeClaimSnapshot pvc = new PersistentVolumeClaimSnapshot();
        pvc.setName("data-pvc");
        pvc.setVolumeName("data-pv");
        pvc.setStorageClassName("standard");
        cluster.setPersistentVolumeClaims(List.of(pvc));
        ClusterRoleBindingSnapshot crb = new ClusterRoleBindingSnapshot();
        crb.setName("admin-binding");
        crb.setSubjectName("admin-sa");
        crb.setClusterRoleName("cluster-admin");
        cluster.setClusterRoleBindings(List.of(crb));
        assertEquals("test-cluster", cluster.getClusterName());
        assertEquals(1, cluster.getNamespaces().size());
        assertEquals("production", cluster.getNamespaces().get(0).getName());
        assertEquals("worker-1", cluster.getNodes().get(0).getName());
        assertEquals("web-sa", cluster.getPods().get(0).getServiceAccountName());
        assertEquals("web", cluster.getServices().get(0).getSelector().get("app"));
        assertEquals(3, cluster.getDeployments().get(0).getReplicas());
        assertEquals("Opaque", cluster.getSecrets().get(0).getSecretType());
        assertEquals("standard", cluster.getPersistentVolumes().get(0).getStorageClassName());
        assertEquals("data-pv", cluster.getPersistentVolumeClaims().get(0).getVolumeName());
        assertEquals("cluster-admin", cluster.getClusterRoleBindings().get(0).getClusterRoleName());
    }

    @Test
    void ingressSnapshot_serviceNameRoundTrips() {
        IngressSnapshot ingress = new IngressSnapshot();
        ingress.setName("web-ingress");
        ingress.setServiceName("web-service");
        assertEquals("web-ingress", ingress.getName());
        assertEquals("web-service", ingress.getServiceName());
    }

    @Test
    void roleBindingSnapshot_subjectAndRoleNameRoundTrip() {
        RoleBindingSnapshot rb = new RoleBindingSnapshot();
        rb.setSubjectName("dev-sa");
        rb.setRoleName("developer-role");
        assertEquals("dev-sa", rb.getSubjectName());
        assertEquals("developer-role", rb.getRoleName());
    }

    @Test
    void clusterRoleSnapshot_rulesRoundTrip() {
        RbacRuleSnapshot rule = new RbacRuleSnapshot();
        rule.setApiGroups(List.of("*"));
        rule.setResources(List.of("*"));
        rule.setVerbs(List.of("*"));
        rule.setResourceNames(List.of());
        ClusterRoleSnapshot cr = new ClusterRoleSnapshot();
        cr.setName("cluster-admin");
        cr.setRules(List.of(rule));
        assertNull(cr.getNamespace());
        assertEquals("cluster-admin", cr.getName());
        assertEquals(1, cr.getRules().size());
        assertTrue(cr.getRules().get(0).getVerbs().contains("*"));
    }

    @Test
    void replicaSetSnapshot_fieldsRoundTrip() {
        Map<String, String> sel = new HashMap<>();
        sel.put("app", "backend");
        ReplicaSetSnapshot rs = new ReplicaSetSnapshot();
        rs.setName("backend-rs");
        rs.setReplicas(2);
        rs.setSelector(sel);
        assertEquals(2, rs.getReplicas());
        assertEquals("backend", rs.getSelector().get("app"));
    }

    @Test
    void serviceAccountSnapshot_commonFieldsRoundTrip() {
        ServiceAccountSnapshot sa = new ServiceAccountSnapshot();
        sa.setUid("sa-uid-001");
        sa.setName("web-sa");
        sa.setNamespace("default");
        assertEquals("sa-uid-001", sa.getUid());
        assertEquals("web-sa", sa.getName());
        assertEquals("default", sa.getNamespace());
    }

    @Test
    void configMapSnapshot_commonFieldsRoundTrip() {
        ConfigMapSnapshot cm = new ConfigMapSnapshot();
        cm.setName("app-config");
        cm.setNamespace("default");
        assertEquals("app-config", cm.getName());
        assertEquals("default", cm.getNamespace());
    }
}
