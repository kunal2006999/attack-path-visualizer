package com.kunal.attackpathvisualizer.scanner;

import com.kunal.attackpathvisualizer.common.model.snapshot.ServiceSnapshot;
import io.fabric8.kubernetes.api.model.Service;
import io.fabric8.kubernetes.api.model.ServiceList;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientException;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

public class ServiceScanner {

    private static final String RESOURCE_CATEGORY = "Services";

    private final KubernetesClient client;

    public ServiceScanner(KubernetesClient client) {
        if (client == null) {
            throw new IllegalArgumentException("KubernetesClient must not be null");
        }
        this.client = client;
    }

    /**
     * Fetches all Services across all namespaces and maps them to {@link ServiceSnapshot} DTOs.
     *
     * @throws ScannerException if the Kubernetes API call fails or returns an unusable response
     */
    public List<ServiceSnapshot> scan() {
        ServiceList serviceList;
        try {
            serviceList = client.services().inAnyNamespace().list();
        } catch (KubernetesClientException e) {
            throw new ScannerException(
                    RESOURCE_CATEGORY,
                    "Kubernetes API call failed while listing " + RESOURCE_CATEGORY
                            + ": " + e.getMessage(),
                    e);
        }

        if (serviceList == null) {
            throw new ScannerException(
                    RESOURCE_CATEGORY,
                    "Kubernetes API returned a null response for " + RESOURCE_CATEGORY
                            + "; cannot distinguish an empty cluster from an API failure",
                    null);
        }

        if (serviceList.getItems() == null) {
            return Collections.emptyList();
        }

        List<ServiceSnapshot> results = new ArrayList<>(serviceList.getItems().size());
        for (Service svc : serviceList.getItems()) {
            results.add(mapToSnapshot(svc));
        }
        return results;
    }

    private ServiceSnapshot mapToSnapshot(Service k8sService) {
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
                try {
                    snapshot.setCreationTimestamp(Instant.from(
                            DateTimeFormatter.ISO_OFFSET_DATE_TIME.parse(
                                    metadata.getCreationTimestamp())));
                } catch (DateTimeParseException e) {
                    throw new ScannerException(
                            RESOURCE_CATEGORY,
                            "Failed to parse creationTimestamp '"
                                    + metadata.getCreationTimestamp()
                                    + "' for Service '" + metadata.getNamespace()
                                    + "/" + metadata.getName() + "'",
                            e);
                }
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
