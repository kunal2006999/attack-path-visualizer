package com.kunal.attackpathvisualizer.scanner;

import com.kunal.attackpathvisualizer.common.model.snapshot.RoleBindingSnapshot;
import io.fabric8.kubernetes.api.model.rbac.RoleBinding;
import io.fabric8.kubernetes.api.model.rbac.RoleBindingList;
import io.fabric8.kubernetes.api.model.rbac.Subject;
import io.fabric8.kubernetes.client.KubernetesClient;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Scans all Kubernetes RoleBindings across all namespaces and maps them to
 * {@link RoleBindingSnapshot} DTOs.
 */
public class RoleBindingScanner {

    private final KubernetesClient client;

    public RoleBindingScanner(KubernetesClient client) {
        this.client = client;
    }

    public List<RoleBindingSnapshot> scan() {
        RoleBindingList roleBindingList = client.rbac().roleBindings().inAnyNamespace().list();

        if (roleBindingList == null || roleBindingList.getItems() == null) {
            return Collections.emptyList();
        }

        return roleBindingList.getItems().stream()
                .map(this::mapToSnapshot)
                .collect(Collectors.toList());
    }

    private RoleBindingSnapshot mapToSnapshot(RoleBinding k8sRoleBinding) {
        RoleBindingSnapshot snapshot = new RoleBindingSnapshot();
        var metadata = k8sRoleBinding.getMetadata();

        if (metadata != null) {
            snapshot.setUid(metadata.getUid());
            snapshot.setName(metadata.getName());
            snapshot.setNamespace(metadata.getNamespace());

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

        // Extract the referenced role name
        var roleRef = k8sRoleBinding.getRoleRef();
        if (roleRef != null) {
            snapshot.setRoleName(roleRef.getName());
        }

        // Extract the names of all subjects (ServiceAccounts, Users, Groups)
        List<Subject> subjects = k8sRoleBinding.getSubjects();
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
