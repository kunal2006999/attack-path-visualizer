package com.kunal.attackpathvisualizer.scanner;

import com.kunal.attackpathvisualizer.common.model.snapshot.RbacRuleSnapshot;
import com.kunal.attackpathvisualizer.common.model.snapshot.RoleSnapshot;
import io.fabric8.kubernetes.api.model.rbac.Role;
import io.fabric8.kubernetes.api.model.rbac.RoleList;
import io.fabric8.kubernetes.api.model.rbac.PolicyRule;
import io.fabric8.kubernetes.client.KubernetesClient;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Scans all Kubernetes Roles across all namespaces and maps them to {@link RoleSnapshot} DTOs.
 */
public class RoleScanner {

    private final KubernetesClient client;

    public RoleScanner(KubernetesClient client) {
        this.client = client;
    }

    public List<RoleSnapshot> scan() {
        RoleList roleList = client.rbac().roles().inAnyNamespace().list();

        if (roleList == null || roleList.getItems() == null) {
            return Collections.emptyList();
        }

        return roleList.getItems().stream()
                .map(this::mapToSnapshot)
                .collect(Collectors.toList());
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
                Instant timestamp = Instant.from(
                        DateTimeFormatter.ISO_OFFSET_DATE_TIME.parse(
                                metadata.getCreationTimestamp()
                        )
                );
                snapshot.setCreationTimestamp(timestamp);
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
