package com.kunal.attackpathvisualizer.scanner;

import com.kunal.attackpathvisualizer.common.model.snapshot.RoleBindingSnapshot;
import com.kunal.attackpathvisualizer.common.model.snapshot.SubjectSnapshot;
import io.fabric8.kubernetes.api.model.rbac.RoleBinding;
import io.fabric8.kubernetes.api.model.rbac.RoleBindingList;
import io.fabric8.kubernetes.api.model.rbac.Subject;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientException;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Scans all Kubernetes RoleBindings across all namespaces and maps them to
 * {@link RoleBindingSnapshot} DTOs.
 */
public class RoleBindingScanner {

    private static final String RESOURCE_CATEGORY = "RoleBindings";

    private final KubernetesClient client;

    public RoleBindingScanner(KubernetesClient client) {
        if (client == null) {
            throw new IllegalArgumentException("KubernetesClient must not be null");
        }
        this.client = client;
    }

    /**
     * Fetches all RoleBindings across all namespaces and maps them to
     * {@link RoleBindingSnapshot} DTOs.
     *
     * @throws ScannerException if the Kubernetes API call fails or returns an unusable response
     */
    public List<RoleBindingSnapshot> scan() {
        RoleBindingList roleBindingList;
        try {
            roleBindingList = client.rbac().roleBindings().inAnyNamespace().list();
        } catch (KubernetesClientException e) {
            throw new ScannerException(
                    RESOURCE_CATEGORY,
                    "Kubernetes API call failed while listing " + RESOURCE_CATEGORY
                            + ": " + e.getMessage(),
                    e);
        }

        if (roleBindingList == null) {
            throw new ScannerException(
                    RESOURCE_CATEGORY,
                    "Kubernetes API returned a null response for " + RESOURCE_CATEGORY
                            + "; cannot distinguish an empty cluster from an API failure",
                    null);
        }

        if (roleBindingList.getItems() == null) {
            return Collections.emptyList();
        }

        List<RoleBindingSnapshot> results = new ArrayList<>(roleBindingList.getItems().size());
        for (RoleBinding rb : roleBindingList.getItems()) {
            results.add(mapToSnapshot(rb));
        }
        return results;
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
                try {
                    snapshot.setCreationTimestamp(Instant.from(
                            DateTimeFormatter.ISO_OFFSET_DATE_TIME.parse(
                                    metadata.getCreationTimestamp())));
                } catch (DateTimeParseException e) {
                    throw new ScannerException(
                            RESOURCE_CATEGORY,
                            "Failed to parse creationTimestamp '"
                                    + metadata.getCreationTimestamp()
                                    + "' for RoleBinding '" + metadata.getNamespace()
                                    + "/" + metadata.getName() + "'",
                            e);
                }
            }
        }

        // Extract the referenced role name
        var roleRef = k8sRoleBinding.getRoleRef();
        if (roleRef != null) {
            snapshot.setRoleName(roleRef.getName());
            snapshot.setRoleKind(roleRef.getKind());
        }

        List<Subject> subjects = k8sRoleBinding.getSubjects();
        if (subjects != null) {
            snapshot.setSubjectNames(subjects.stream()
                    .map(Subject::getName)
                    .collect(Collectors.toList()));
            snapshot.setSubjects(subjects.stream()
                    .map(s -> SubjectSnapshot.of(s.getKind(), s.getName(), s.getNamespace()))
                    .collect(Collectors.toList()));
        } else {
            snapshot.setSubjectNames(Collections.emptyList());
            snapshot.setSubjects(Collections.emptyList());
        }

        return snapshot;
    }
}
