package com.kunal.attackpathvisualizer.scanner;

import com.kunal.attackpathvisualizer.common.model.snapshot.NamespaceSnapshot;
import io.fabric8.kubernetes.api.model.Namespace;
import io.fabric8.kubernetes.api.model.NamespaceList;
import io.fabric8.kubernetes.client.KubernetesClient;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;

public class NamespaceScanner {

    private final KubernetesClient client;

    public NamespaceScanner(KubernetesClient client) {
        this.client = client;
    }

    public List<NamespaceSnapshot> scan() {

        NamespaceList namespaceList = client.namespaces().list();

        if (namespaceList == null || namespaceList.getItems() == null) {
            return Collections.emptyList();
        }

        return namespaceList.getItems().stream()
                .map(this::mapToSnapshot)
                .collect(Collectors.toList());
    }

    private NamespaceSnapshot mapToSnapshot(io.fabric8.kubernetes.api.model.Namespace k8sNamespace) {
        NamespaceSnapshot snapshot = new NamespaceSnapshot();
        var metadata = k8sNamespace.getMetadata();

        if (metadata != null) {
            snapshot.setUid(metadata.getUid());
            snapshot.setName(metadata.getName());

            // Namespaces are cluster-scoped, so their namespace property is null
            snapshot.setNamespace(null);

            // Copy into new maps rather than exposing Fabric8's mutable structures
            snapshot.setLabels(metadata.getLabels() != null
                    ? new HashMap<>(metadata.getLabels())
                    : Collections.emptyMap());
            snapshot.setAnnotations(metadata.getAnnotations() != null
                    ? new HashMap<>(metadata.getAnnotations())
                    : Collections.emptyMap());

            // Convert Kubernetes RFC 3339 timestamp string into java.time.Instant
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
