package com.kunal.attackpathvisualizer.scanner;

import com.kunal.attackpathvisualizer.common.model.snapshot.ClusterRoleBindingSnapshot;
import com.kunal.attackpathvisualizer.common.model.snapshot.SubjectSnapshot;
import io.fabric8.kubernetes.api.model.rbac.ClusterRoleBinding;
import io.fabric8.kubernetes.api.model.rbac.ClusterRoleBindingList;
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
 * Scans all Kubernetes ClusterRoleBindings (cluster-scoped) and maps them to
 * {@link ClusterRoleBindingSnapshot} DTOs.
 */
public class ClusterRoleBindingScanner {

    private static final String RESOURCE_CATEGORY = "ClusterRoleBindings";

    private final KubernetesClient client;

    public ClusterRoleBindingScanner(KubernetesClient client) {
        if (client == null) {
            throw new IllegalArgumentException("KubernetesClient must not be null");
        }
        this.client = client;
    }

    /**
     * Fetches all ClusterRoleBindings and maps them to {@link ClusterRoleBindingSnapshot} DTOs.
     *
     * @throws ScannerException if the Kubernetes API call fails or returns an unusable response
     */
    public List<ClusterRoleBindingSnapshot> scan() {
        ClusterRoleBindingList clusterRoleBindingList;
        try {
            clusterRoleBindingList = client.rbac().clusterRoleBindings().list();
        } catch (KubernetesClientException e) {
            throw new ScannerException(
                    RESOURCE_CATEGORY,
                    "Kubernetes API call failed while listing " + RESOURCE_CATEGORY
                            + ": " + e.getMessage(),
                    e);
        }

        if (clusterRoleBindingList == null) {
            throw new ScannerException(
                    RESOURCE_CATEGORY,
                    "Kubernetes API returned a null response for " + RESOURCE_CATEGORY
                            + "; cannot distinguish an empty cluster from an API failure",
                    null);
        }

        if (clusterRoleBindingList.getItems() == null) {
            return Collections.emptyList();
        }

        List<ClusterRoleBindingSnapshot> results =
                new ArrayList<>(clusterRoleBindingList.getItems().size());
        for (ClusterRoleBinding crb : clusterRoleBindingList.getItems()) {
            results.add(mapToSnapshot(crb));
        }
        return results;
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
                try {
                    snapshot.setCreationTimestamp(Instant.from(
                            DateTimeFormatter.ISO_OFFSET_DATE_TIME.parse(
                                    metadata.getCreationTimestamp())));
                } catch (DateTimeParseException e) {
                    throw new ScannerException(
                            RESOURCE_CATEGORY,
                            "Failed to parse creationTimestamp '"
                                    + metadata.getCreationTimestamp()
                                    + "' for ClusterRoleBinding '" + metadata.getName() + "'",
                            e);
                }
            }
        }

        // Extract the referenced ClusterRole name
        var roleRef = k8sClusterRoleBinding.getRoleRef();
        if (roleRef != null) {
            snapshot.setClusterRoleName(roleRef.getName());
        }

        List<Subject> subjects = k8sClusterRoleBinding.getSubjects();
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
