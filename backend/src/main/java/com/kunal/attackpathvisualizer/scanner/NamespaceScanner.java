package com.kunal.attackpathvisualizer.scanner;

import com.kunal.attackpathvisualizer.common.model.snapshot.NamespaceSnapshot;
import io.fabric8.kubernetes.api.model.Namespace;
import io.fabric8.kubernetes.api.model.NamespaceList;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientException;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

public class NamespaceScanner {

    private static final String RESOURCE_CATEGORY = "Namespaces";

    private final KubernetesClient client;

    public NamespaceScanner(KubernetesClient client) {
        if (client == null) {
            throw new IllegalArgumentException("KubernetesClient must not be null");
        }
        this.client = client;
    }

    /**
     * Fetches all Namespaces from the cluster and maps them to {@link NamespaceSnapshot} DTOs.
     *
     * @throws ScannerException if the Kubernetes API call fails or returns an unusable response
     */
    public List<NamespaceSnapshot> scan() {
        NamespaceList namespaceList;
        try {
            namespaceList = client.namespaces().list();
        } catch (KubernetesClientException e) {
            throw new ScannerException(
                    RESOURCE_CATEGORY,
                    "Kubernetes API call failed while listing " + RESOURCE_CATEGORY
                            + ": " + e.getMessage(),
                    e);
        }

        if (namespaceList == null) {
            throw new ScannerException(
                    RESOURCE_CATEGORY,
                    "Kubernetes API returned a null response for " + RESOURCE_CATEGORY
                            + "; cannot distinguish an empty cluster from an API failure",
                    null);
        }

        if (namespaceList.getItems() == null) {
            // An explicit null items list from the API server is anomalous but not impossible
            // during a partial/degraded response. Return empty rather than a null-items crash.
            return Collections.emptyList();
        }

        List<NamespaceSnapshot> results = new ArrayList<>(namespaceList.getItems().size());
        for (Namespace ns : namespaceList.getItems()) {
            results.add(mapToSnapshot(ns));
        }
        return results;
    }

    private NamespaceSnapshot mapToSnapshot(Namespace k8sNamespace) {
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
                try {
                    snapshot.setCreationTimestamp(Instant.from(
                            DateTimeFormatter.ISO_OFFSET_DATE_TIME.parse(
                                    metadata.getCreationTimestamp())));
                } catch (DateTimeParseException e) {
                    throw new ScannerException(
                            RESOURCE_CATEGORY,
                            "Failed to parse creationTimestamp '"
                                    + metadata.getCreationTimestamp()
                                    + "' for Namespace '" + metadata.getName() + "'",
                            e);
                }
            }
        }

        return snapshot;
    }
}
