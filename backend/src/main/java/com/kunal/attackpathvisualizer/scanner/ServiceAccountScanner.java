package com.kunal.attackpathvisualizer.scanner;

import com.kunal.attackpathvisualizer.common.model.snapshot.ServiceAccountSnapshot;
import io.fabric8.kubernetes.api.model.ServiceAccountList;
import io.fabric8.kubernetes.client.KubernetesClient;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;

public class ServiceAccountScanner {

    private final KubernetesClient client;

    public ServiceAccountScanner(KubernetesClient client) {
        this.client = client;
    }

    public List<ServiceAccountSnapshot> scan() {

        ServiceAccountList serviceAccountList = client.serviceAccounts().inAnyNamespace().list();

        if (serviceAccountList == null || serviceAccountList.getItems() == null) {
            return Collections.emptyList();
        }

        return serviceAccountList.getItems().stream()
                .map(this::mapToSnapshot)
                .collect(Collectors.toList());
    }

    private ServiceAccountSnapshot mapToSnapshot(io.fabric8.kubernetes.api.model.ServiceAccount k8sServiceAccount) {
        ServiceAccountSnapshot snapshot = new ServiceAccountSnapshot();
        var metadata = k8sServiceAccount.getMetadata();

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

        return snapshot;
    }
}