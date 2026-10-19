package com.kunal.attackpathvisualizer.scanner;

import com.kunal.attackpathvisualizer.common.model.snapshot.ClusterRoleSnapshot;
import com.kunal.attackpathvisualizer.common.model.snapshot.RbacRuleSnapshot;
import io.fabric8.kubernetes.api.model.rbac.ClusterRole;
import io.fabric8.kubernetes.api.model.rbac.ClusterRoleList;
import io.fabric8.kubernetes.api.model.rbac.PolicyRule;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientException;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

/**
 * Scans all Kubernetes ClusterRoles (cluster-scoped) and maps them to {@link ClusterRoleSnapshot} DTOs.
 */
public class ClusterRoleScanner {

    private static final String RESOURCE_CATEGORY = "ClusterRoles";

    private final KubernetesClient client;

    public ClusterRoleScanner(KubernetesClient client) {
        if (client == null) {
            throw new IllegalArgumentException("KubernetesClient must not be null");
        }
        this.client = client;
    }

    /**
     * Fetches all ClusterRoles and maps them to {@link ClusterRoleSnapshot} DTOs.
     *
     * @throws ScannerException if the Kubernetes API call fails or returns an unusable response
     */
    public List<ClusterRoleSnapshot> scan() {
        ClusterRoleList clusterRoleList;
        try {
            clusterRoleList = client.rbac().clusterRoles().list();
        } catch (KubernetesClientException e) {
            throw new ScannerException(
                    RESOURCE_CATEGORY,
                    "Kubernetes API call failed while listing " + RESOURCE_CATEGORY
                            + ": " + e.getMessage(),
                    e);
        }

        if (clusterRoleList == null) {
            throw new ScannerException(
                    RESOURCE_CATEGORY,
                    "Kubernetes API returned a null response for " + RESOURCE_CATEGORY
                            + "; cannot distinguish an empty cluster from an API failure",
                    null);
        }

        if (clusterRoleList.getItems() == null) {
            return Collections.emptyList();
        }

        List<ClusterRoleSnapshot> results = new ArrayList<>(clusterRoleList.getItems().size());
        for (ClusterRole cr : clusterRoleList.getItems()) {
            results.add(mapToSnapshot(cr));
        }
        return results;
    }

    private ClusterRoleSnapshot mapToSnapshot(ClusterRole k8sClusterRole) {
        ClusterRoleSnapshot snapshot = new ClusterRoleSnapshot();
        var metadata = k8sClusterRole.getMetadata();

        if (metadata != null) {
            snapshot.setUid(metadata.getUid());
            snapshot.setName(metadata.getName());

            // ClusterRoles are cluster-scoped; namespace is null
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
                                    + "' for ClusterRole '" + metadata.getName() + "'",
                            e);
                }
            }
        }

        snapshot.setRules(mapRules(k8sClusterRole.getRules()));

        return snapshot;
    }

    private List<RbacRuleSnapshot> mapRules(List<PolicyRule> k8sRules) {
        if (k8sRules == null) {
            return Collections.emptyList();
        }
        List<RbacRuleSnapshot> rules = new ArrayList<>();
        for (PolicyRule k8sRule : k8sRules) {
            RbacRuleSnapshot rule = new RbacRuleSnapshot();
            rule.setApiGroups(k8sRule.getApiGroups() != null
                    ? new ArrayList<>(k8sRule.getApiGroups())
                    : Collections.emptyList());
            rule.setResources(k8sRule.getResources() != null
                    ? new ArrayList<>(k8sRule.getResources())
                    : Collections.emptyList());
            rule.setVerbs(k8sRule.getVerbs() != null
                    ? new ArrayList<>(k8sRule.getVerbs())
                    : Collections.emptyList());
            rule.setResourceNames(k8sRule.getResourceNames() != null
                    ? new ArrayList<>(k8sRule.getResourceNames())
                    : Collections.emptyList());
            rules.add(rule);
        }
        return rules;
    }
}
