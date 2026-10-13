package com.kunal.attackpathvisualizer.scanner;

import com.kunal.attackpathvisualizer.common.model.snapshot.PodSnapshot;
import io.fabric8.kubernetes.api.model.PodList;
import io.fabric8.kubernetes.client.KubernetesClient;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;

public class PodScanner {

    private final KubernetesClient client;

    public PodScanner(KubernetesClient client) {
        this.client = client;
    }

    public List<PodSnapshot> scan() {

        PodList podList = client.pods().inAnyNamespace().list();

        if (podList == null || podList.getItems() == null) {
            return Collections.emptyList();
        }

        return podList.getItems().stream()
                .map(this::mapToSnapshot)
                .collect(Collectors.toList());
    }

    private PodSnapshot mapToSnapshot(io.fabric8.kubernetes.api.model.Pod k8sPod) {
        PodSnapshot snapshot = new PodSnapshot();
        var metadata = k8sPod.getMetadata();

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

        var spec = k8sPod.getSpec();
        if (spec != null) {
            snapshot.setServiceAccountName(spec.getServiceAccountName());
        }

        return snapshot;
    }
}
