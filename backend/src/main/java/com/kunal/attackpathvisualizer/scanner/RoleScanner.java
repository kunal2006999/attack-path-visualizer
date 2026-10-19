package com.kunal.attackpathvisualizer.scanner;

import com.kunal.attackpathvisualizer.common.model.snapshot.RbacRuleSnapshot;
import com.kunal.attackpathvisualizer.common.model.snapshot.RoleSnapshot;
import io.fabric8.kubernetes.api.model.rbac.PolicyRule;
import io.fabric8.kubernetes.api.model.rbac.Role;
import io.fabric8.kubernetes.api.model.rbac.RoleList;
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
 * Scans all Kubernetes Roles across all namespaces and maps them to {@link RoleSnapshot} DTOs.
 */
public class RoleScanner {

    private static final String RESOURCE_CATEGORY = "Roles";

    private final KubernetesClient client;

    public RoleScanner(KubernetesClient client) {
        if (client == null) {
            throw new IllegalArgumentException("KubernetesClient must not be null");
        }
        this.client = client;
    }

    /**
     * Fetches all Roles across all namespaces and maps them to {@link RoleSnapshot} DTOs.
     *
     * @throws ScannerException if the Kubernetes API call fails or returns an unusable response
     */
    public List<RoleSnapshot> scan() {
        RoleList roleList;
        try {
            roleList = client.rbac().roles().inAnyNamespace().list();
        } catch (KubernetesClientException e) {
            throw new ScannerException(
                    RESOURCE_CATEGORY,
                    "Kubernetes API call failed while listing " + RESOURCE_CATEGORY
                            + ": " + e.getMessage(),
                    e);
        }

        if (roleList == null) {
            throw new ScannerException(
                    RESOURCE_CATEGORY,
                    "Kubernetes API returned a null response for " + RESOURCE_CATEGORY
                            + "; cannot distinguish an empty cluster from an API failure",
                    null);
        }

        if (roleList.getItems() == null) {
            return Collections.emptyList();
        }

        List<RoleSnapshot> results = new ArrayList<>(roleList.getItems().size());
        for (Role role : roleList.getItems()) {
            results.add(mapToSnapshot(role));
        }
        return results;
    }

    private RoleSnapshot mapToSnapshot(Role k8sRole) {
        RoleSnapshot snapshot = new RoleSnapshot();
        var metadata = k8sRole.getMetadata();

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
                                    + "' for Role '" + metadata.getNamespace()
                                    + "/" + metadata.getName() + "'",
                            e);
                }
            }
        }

        snapshot.setRules(mapRules(k8sRole.getRules()));

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
