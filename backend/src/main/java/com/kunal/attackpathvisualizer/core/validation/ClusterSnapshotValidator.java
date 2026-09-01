package com.kunal.attackpathvisualizer.core.validation;

import com.kunal.attackpathvisualizer.common.model.snapshot.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

@org.springframework.stereotype.Component
public class ClusterSnapshotValidator {

    public void validate(ClusterSnapshot snapshot) {

        if (snapshot == null) {
            throw new IllegalArgumentException("Cluster snapshot cannot be null");
        }

        if (isBlank(snapshot.getClusterName())) {
            throw new IllegalArgumentException(
                    "Cluster name cannot be empty"
            );
        }

        validateResources(snapshot);
    }

    private void validateResources(ClusterSnapshot snapshot) {

        Set<String> uids = new HashSet<>();

        validateResourceList(
                snapshot.getNamespaces(),
                uids
        );

        validateResourceList(
                snapshot.getNodes(),
                uids
        );

        validateResourceList(
                snapshot.getPods(),
                uids
        );

        validateResourceList(
                snapshot.getDeployments(),
                uids
        );

        validateResourceList(
                snapshot.getReplicaSets(),
                uids
        );

        validateResourceList(
                snapshot.getServices(),
                uids
        );

        validateResourceList(
                snapshot.getIngresses(),
                uids
        );

        validateResourceList(
                snapshot.getServiceAccounts(),
                uids
        );

        validateResourceList(
                snapshot.getRoles(),
                uids
        );

        validateResourceList(
                snapshot.getClusterRoles(),
                uids
        );

        validateResourceList(
                snapshot.getRoleBindings(),
                uids
        );

        validateResourceList(
                snapshot.getClusterRoleBindings(),
                uids
        );

        validateResourceList(
                snapshot.getSecrets(),
                uids
        );

        validateResourceList(
                snapshot.getConfigMaps(),
                uids
        );

        validateResourceList(
                snapshot.getPersistentVolumes(),
                uids
        );

        validateResourceList(
                snapshot.getPersistentVolumeClaims(),
                uids
        );
    }

    private void validateResourceList(
            List<? extends ResourceSnapshot> resources,
            Set<String> uids) {

        if (resources == null) {
            return;
        }

        for (ResourceSnapshot resource : resources) {

            if (resource == null) {
                throw new IllegalArgumentException(
                        "Resource cannot be null in list"
                );
            }

            if (isBlank(resource.getUid())) {
                throw new IllegalArgumentException(
                        "Resource UID cannot be empty for " + resource.getClass().getSimpleName()
                );
            }

            if (isBlank(resource.getName())) {
                throw new IllegalArgumentException(
                        "Resource name cannot be empty (UID: " + resource.getUid() + ")"
                );
            }

            if (!uids.add(resource.getUid())) {
                throw new IllegalArgumentException(
                        "Duplicate resource UID: "
                                + resource.getUid()
                                + " (" + resource.getName() + ")"
                );
            }
        }
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}