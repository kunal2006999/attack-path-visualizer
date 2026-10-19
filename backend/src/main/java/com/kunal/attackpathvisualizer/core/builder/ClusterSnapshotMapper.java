package com.kunal.attackpathvisualizer.core.builder;

import com.kunal.attackpathvisualizer.common.model.snapshot.*;
import com.kunal.attackpathvisualizer.core.model.*;

import java.util.Collections;
import java.util.List;

/** Maps a ClusterSnapshot to the core Cluster model, then delegates relationship building. */
@org.springframework.stereotype.Component
public class ClusterSnapshotMapper {

    private final ClusterRelationshipBuilder relationshipBuilder = new ClusterRelationshipBuilder();

    public Cluster map(ClusterSnapshot snapshot) {
        if (snapshot == null) {
            throw new IllegalArgumentException("Cluster snapshot cannot be null");
        }

        Cluster cluster = new Cluster(snapshot.getClusterName());

        for (NamespaceSnapshot r : safe(snapshot.getNamespaces())) cluster.addResource(mapNamespace(r));
        for (NodeSnapshot r : safe(snapshot.getNodes())) cluster.addResource(mapNode(r));
        for (PodSnapshot r : safe(snapshot.getPods())) cluster.addResource(mapPod(r));
        for (DeploymentSnapshot r : safe(snapshot.getDeployments())) cluster.addResource(mapDeployment(r));
        for (ReplicaSetSnapshot r : safe(snapshot.getReplicaSets())) cluster.addResource(mapReplicaSet(r));
        for (ServiceSnapshot r : safe(snapshot.getServices())) cluster.addResource(mapService(r));
        for (IngressSnapshot r : safe(snapshot.getIngresses())) cluster.addResource(mapIngress(r));
        for (ServiceAccountSnapshot r : safe(snapshot.getServiceAccounts())) cluster.addResource(mapServiceAccount(r));
        for (RoleSnapshot r : safe(snapshot.getRoles())) cluster.addResource(mapRole(r));
        for (ClusterRoleSnapshot r : safe(snapshot.getClusterRoles())) cluster.addResource(mapClusterRole(r));
        for (RoleBindingSnapshot r : safe(snapshot.getRoleBindings())) cluster.addResource(mapRoleBinding(r));
        for (ClusterRoleBindingSnapshot r : safe(snapshot.getClusterRoleBindings())) cluster.addResource(mapClusterRoleBinding(r));
        for (SecretSnapshot r : safe(snapshot.getSecrets())) cluster.addResource(mapSecret(r));
        for (ConfigMapSnapshot r : safe(snapshot.getConfigMaps())) cluster.addResource(mapConfigMap(r));
        for (PersistentVolumeSnapshot r : safe(snapshot.getPersistentVolumes())) cluster.addResource(mapPersistentVolume(r));
        for (PersistentVolumeClaimSnapshot r : safe(snapshot.getPersistentVolumeClaims())) cluster.addResource(mapPersistentVolumeClaim(r));

        relationshipBuilder.build(cluster);

        return cluster;
    }

    private Namespace mapNamespace(NamespaceSnapshot r) {
        return new Namespace(r.getUid(), r.getName(), r.getLabels(), r.getAnnotations(), r.getCreationTimestamp());
    }

    private Node mapNode(NodeSnapshot r) {
        return new Node(r.getUid(), r.getName(), r.getLabels(), r.getAnnotations(), r.getCreationTimestamp());
    }

    private Pod mapPod(PodSnapshot r) {
        return new Pod(r.getUid(), r.getName(), r.getNamespace(), r.getLabels(), r.getAnnotations(),
                r.getCreationTimestamp(), r.getServiceAccountName());
    }

    private Deployment mapDeployment(DeploymentSnapshot r) {
        return new Deployment(r.getUid(), r.getName(), r.getNamespace(), r.getLabels(), r.getAnnotations(),
                r.getCreationTimestamp(), r.getReplicas(), r.getSelector());
    }

    private ReplicaSet mapReplicaSet(ReplicaSetSnapshot r) {
        return new ReplicaSet(r.getUid(), r.getName(), r.getNamespace(), r.getLabels(), r.getAnnotations(),
                r.getCreationTimestamp(), r.getReplicas(), r.getSelector());
    }

    private Service mapService(ServiceSnapshot r) {
        return new Service(r.getUid(), r.getName(), r.getNamespace(), r.getLabels(), r.getAnnotations(),
                r.getCreationTimestamp(), r.getSelector());
    }

    private Ingress mapIngress(IngressSnapshot r) {
        return new Ingress(r.getUid(), r.getName(), r.getNamespace(), r.getLabels(), r.getAnnotations(),
                r.getCreationTimestamp(), r.getServiceName());
    }

    private ServiceAccount mapServiceAccount(ServiceAccountSnapshot r) {
        return new ServiceAccount(r.getUid(), r.getName(), r.getNamespace(), r.getLabels(), r.getAnnotations(),
                r.getCreationTimestamp());
    }

    private Role mapRole(RoleSnapshot r) {
        return new Role(r.getUid(), r.getName(), r.getNamespace(), r.getLabels(), r.getAnnotations(),
                r.getCreationTimestamp(), mapRules(r.getRules()));
    }

    private ClusterRole mapClusterRole(ClusterRoleSnapshot r) {
        return new ClusterRole(r.getUid(), r.getName(), r.getLabels(), r.getAnnotations(),
                r.getCreationTimestamp(), mapRules(r.getRules()));
    }

    private RoleBinding mapRoleBinding(RoleBindingSnapshot r) {
        return new RoleBinding(r.getUid(), r.getName(), r.getNamespace(), r.getLabels(), r.getAnnotations(),
                r.getCreationTimestamp(), r.getRoleName(), r.getRoleKind(),
                mapSubjects(r.getSubjects(), r.getSubjectNames()));
    }

    private ClusterRoleBinding mapClusterRoleBinding(ClusterRoleBindingSnapshot r) {
        return new ClusterRoleBinding(r.getUid(), r.getName(), r.getLabels(), r.getAnnotations(),
                r.getCreationTimestamp(), r.getClusterRoleName(),
                mapSubjects(r.getSubjects(), r.getSubjectNames()));
    }

    private Secret mapSecret(SecretSnapshot r) {
        return new Secret(r.getUid(), r.getName(), r.getNamespace(), r.getLabels(), r.getAnnotations(),
                r.getCreationTimestamp(), r.getSecretType());
    }

    private ConfigMap mapConfigMap(ConfigMapSnapshot r) {
        return new ConfigMap(r.getUid(), r.getName(), r.getNamespace(), r.getLabels(), r.getAnnotations(),
                r.getCreationTimestamp());
    }

    private PersistentVolume mapPersistentVolume(PersistentVolumeSnapshot r) {
        return new PersistentVolume(r.getUid(), r.getName(), r.getLabels(), r.getAnnotations(),
                r.getCreationTimestamp(), r.getStorageClassName());
    }

    private PersistentVolumeClaim mapPersistentVolumeClaim(PersistentVolumeClaimSnapshot r) {
        return new PersistentVolumeClaim(r.getUid(), r.getName(), r.getNamespace(), r.getLabels(),
                r.getAnnotations(), r.getCreationTimestamp(), r.getVolumeName(), r.getStorageClassName());
    }

    private List<RbacRule> mapRules(List<RbacRuleSnapshot> rules) {
        return safe(rules).stream()
                .filter(rule -> rule != null)
                .map(rule -> new RbacRule(
                        rule.getApiGroups(),
                        rule.getResources(),
                        rule.getVerbs(),
                        rule.getResourceNames()))
                .toList();
    }

    /** Prefers full subjects (kind + namespace); falls back to legacy names as namespace-less ServiceAccounts. */
    private List<RbacSubject> mapSubjects(List<SubjectSnapshot> subjects, List<String> legacyNames) {
        if (subjects != null && !subjects.isEmpty()) {
            return subjects.stream()
                    .filter(s -> s != null)
                    .map(s -> new RbacSubject(s.getKind(), s.getName(), s.getNamespace()))
                    .toList();
        }
        return RbacSubject.fromServiceAccountNames(legacyNames);
    }

    private static <T> List<T> safe(List<T> list) {
        return list == null ? Collections.emptyList() : list;
    }
}