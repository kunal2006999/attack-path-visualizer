package com.kunal.attackpathvisualizer.scanner;

import com.kunal.attackpathvisualizer.common.model.snapshot.ServiceSnapshot;
import io.fabric8.kubernetes.api.model.ServiceList;
import io.fabric8.kubernetes.client.KubernetesClient;

import java.util.*;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.stream.Collectors;

public class ServiceScanner {
    private final KubernetesClient client;

    public ServiceScanner(KubernetesClient client) {
        this.client = client;
    }

    public List<ServiceSnapshot> scan() {

        ServiceList serviceList = client.services().inAnyNamespace().list();

        if (serviceList == null || serviceList.getItems() == null) {
            return Collections.emptyList();
        }

        return serviceList.getItems().stream()
                .map(this::mapToSnapshot)
                .collect(Collectors.toList());
    }

    private ServiceSnapshot mapToSnapshot(io.fabric8.kubernetes.api.model.Service k8sService) {
        ServiceSnapshot snapshot = new ServiceSnapshot();
        var metadata = k8sService.getMetadata();

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

        var spec = k8sService.getSpec();
        if (spec != null) {
            snapshot.setSelector(spec.getSelector() != null
                    ? new HashMap<>(spec.getSelector())
                    : Collections.emptyMap());
        }

        return snapshot;
    }
}
