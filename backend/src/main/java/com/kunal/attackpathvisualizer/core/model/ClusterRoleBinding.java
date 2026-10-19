package com.kunal.attackpathvisualizer.core.model;

import com.kunal.attackpathvisualizer.core.enums.ResourceType;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public class ClusterRoleBinding extends KubernetesResource {
    private final List<RbacSubject> subjects;
    private final String clusterRoleName;

    /** Legacy constructor: names carry no namespace, so they cannot be resolved to ServiceAccounts. */
    public ClusterRoleBinding(
            String uid,
            String name,
            Map<String, String> labels,
            Map<String, String> annotations,
            Instant creationTimestamp,
            List<String> subjectNames,
            String clusterRoleName) {
        this(uid, name, labels, annotations, creationTimestamp,
                clusterRoleName, RbacSubject.fromServiceAccountNames(subjectNames));
    }

    public ClusterRoleBinding(
            String uid,
            String name,
            Map<String, String> labels,
            Map<String, String> annotations,
            Instant creationTimestamp,
            String clusterRoleName,
            List<RbacSubject> subjects) {

        super(uid, name, null, ResourceType.CLUSTER_ROLE_BINDING, labels, annotations, creationTimestamp);

        this.clusterRoleName = clusterRoleName;
        this.subjects = subjects == null ? List.of() : List.copyOf(subjects);
    }

    public List<RbacSubject> getSubjects() {
        return subjects;
    }

    public List<String> getSubjectNames() {
        return subjects.stream().map(RbacSubject::getName).toList();
    }

    public String getClusterRoleName() {
        return clusterRoleName;
    }
}