package com.kunal.attackpathvisualizer.scanner;

import com.kunal.attackpathvisualizer.common.model.snapshot.ClusterRoleBindingSnapshot;
import io.fabric8.kubernetes.api.model.rbac.ClusterRoleBinding;
import io.fabric8.kubernetes.api.model.rbac.ClusterRoleBindingList;
import io.fabric8.kubernetes.api.model.rbac.Subject;
import io.fabric8.kubernetes.client.KubernetesClient;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Scans all Kubernetes ClusterRoleBindings (cluster-scoped) and maps them to
 * {@link ClusterRoleBindingSnapshot} DTOs.
 */
public class ClusterRoleBindingScanner {

    private final KubernetesClient client;

    public ClusterRoleBindingScanner(KubernetesClient client) {
        this.client = client;
    }

    public List<ClusterRoleBindingSnapshot> scan() {
        ClusterRoleBindingList clusterRoleBindingList = client.rbac().clusterRoleBindings().list();

        if (clusterRoleBindingList == null || clusterRoleBindingList.getItems() == null) {
            return Collections.emptyList();
        }

        return clusterRoleBindingList.getItems().stream()
                .map(this::mapToSnapshot)
                .collect(Collectors.toList());
    }

    private ClusterRoleBindingSnapshot mapToSnapshot(ClusterRoleBinding k8sClusterRoleBinding) {
        ClusterRoleBindingSnapshot snapshot = new ClusterRoleBindingSnapshot();
        var metadata = k8sClusterRoleBinding.getMetadata();

        if (metadata != null) {
            snapshot.setUid(metadata.getUid());
            snapshot.setName(metadata.getName());

            // ClusterRoleBindings are cluster-scoped; namespace is null
            snapshot.setNamespace(null);

            snapshot.setLabels(metadata.getLabels() != null
                    ? new HashMap<>(metadata.getLabels())
                    : Collections.emptyMap());
            snapshot.setAnnotations(metadata.getAnnotations() != null
                    ? new HashMap<>(metadata.getAnnotations())
                    : Collections.emptyMap());

            if (metadata.getCreationTimestamp() != null) {
                Instant timestamp = Instant.from(
                        DateTimeFormatter.ISO_OFFSET_DATE_TIME.parse(
                                metadata.getCreationTimestamp()
                        )
                );
                snapshot.setCreationTimestamp(timestamp);
            }
        }

        // Extract the referenced ClusterRole name
        var roleRef = k8sClusterRoleBinding.getRoleRef();
        if (roleRef != null) {
            snapshot.setClusterRoleName(roleRef.getName());
        }

        // Extract the names of all subjects (ServiceAccounts, Users, Groups)
        List<Subject> subjects = k8sClusterRoleBinding.getSubjects();
        if (subjects != null) {
            List<String> subjectNames = subjects.stream()
                    .map(Subject::getName)
                    .collect(Collectors.toList());
            snapshot.setSubjectNames(subjectNames);
        } else {
            snapshot.setSubjectNames(Collections.emptyList());
        }

        return snapshot;
    }
}
