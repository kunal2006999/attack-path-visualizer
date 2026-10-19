package com.kunal.attackpathvisualizer.scanner;

import com.kunal.attackpathvisualizer.common.model.snapshot.ServiceAccountSnapshot;
import io.fabric8.kubernetes.api.model.ServiceAccount;
import io.fabric8.kubernetes.api.model.ServiceAccountList;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientException;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

public class ServiceAccountScanner {

    private static final String RESOURCE_CATEGORY = "ServiceAccounts";

    private final KubernetesClient client;

    public ServiceAccountScanner(KubernetesClient client) {
        if (client == null) {
            throw new IllegalArgumentException("KubernetesClient must not be null");
        }
        this.client = client;
    }

    /**
     * Fetches all ServiceAccounts across all namespaces and maps them to
     * {@link ServiceAccountSnapshot} DTOs.
     *
     * @throws ScannerException if the Kubernetes API call fails or returns an unusable response
     */
    public List<ServiceAccountSnapshot> scan() {
        ServiceAccountList serviceAccountList;
        try {
            serviceAccountList = client.serviceAccounts().inAnyNamespace().list();
        } catch (KubernetesClientException e) {
            throw new ScannerException(
                    RESOURCE_CATEGORY,
                    "Kubernetes API call failed while listing " + RESOURCE_CATEGORY
                            + ": " + e.getMessage(),
                    e);
        }

        if (serviceAccountList == null) {
            throw new ScannerException(
                    RESOURCE_CATEGORY,
                    "Kubernetes API returned a null response for " + RESOURCE_CATEGORY
                            + "; cannot distinguish an empty cluster from an API failure",
                    null);
        }

        if (serviceAccountList.getItems() == null) {
            return Collections.emptyList();
        }

        List<ServiceAccountSnapshot> results = new ArrayList<>(serviceAccountList.getItems().size());
        for (ServiceAccount sa : serviceAccountList.getItems()) {
            results.add(mapToSnapshot(sa));
        }
        return results;
    }

    private ServiceAccountSnapshot mapToSnapshot(ServiceAccount k8sServiceAccount) {
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
                try {
                    snapshot.setCreationTimestamp(Instant.from(
                            DateTimeFormatter.ISO_OFFSET_DATE_TIME.parse(
                                    metadata.getCreationTimestamp())));
                } catch (DateTimeParseException e) {
                    throw new ScannerException(
                            RESOURCE_CATEGORY,
                            "Failed to parse creationTimestamp '"
                                    + metadata.getCreationTimestamp()
                                    + "' for ServiceAccount '" + metadata.getNamespace()
                                    + "/" + metadata.getName() + "'",
                            e);
                }
            }
        }

        return snapshot;
    }
}