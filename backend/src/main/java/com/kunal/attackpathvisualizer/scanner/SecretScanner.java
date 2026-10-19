package com.kunal.attackpathvisualizer.scanner;

import com.kunal.attackpathvisualizer.common.model.snapshot.SecretSnapshot;
import io.fabric8.kubernetes.api.model.Secret;
import io.fabric8.kubernetes.api.model.SecretList;
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
 * Scans all Kubernetes Secrets across all namespaces and maps them to {@link SecretSnapshot} DTOs.
 *
 * <p>NOTE: Secret {@code data} values are intentionally NOT captured — only metadata and the
 * secret type are recorded, to avoid handling sensitive material in memory.
 * Error messages produced by this scanner never include secret name/namespace combinations
 * beyond what is already visible from metadata (which does not contain secret values).
 */
public class SecretScanner {

    private static final String RESOURCE_CATEGORY = "Secrets";

    private final KubernetesClient client;

    public SecretScanner(KubernetesClient client) {
        if (client == null) {
            throw new IllegalArgumentException("KubernetesClient must not be null");
        }
        this.client = client;
    }

    /**
     * Fetches all Secrets across all namespaces and maps them to {@link SecretSnapshot} DTOs.
     *
     * <p>Only metadata (UID, name, namespace, labels, annotations, creation timestamp) and
     * {@code type} are captured. Secret {@code data} is never read or stored.
     *
     * @throws ScannerException if the Kubernetes API call fails or returns an unusable response
     */
    public List<SecretSnapshot> scan() {
        SecretList secretList;
        try {
            secretList = client.secrets().inAnyNamespace().list();
        } catch (KubernetesClientException e) {
            // Do NOT include any secret values in the exception message.
            // The KubernetesClientException message from Fabric8 does not contain secret data.
            throw new ScannerException(
                    RESOURCE_CATEGORY,
                    "Kubernetes API call failed while listing " + RESOURCE_CATEGORY
                            + ": " + e.getMessage(),
                    e);
        }

        if (secretList == null) {
            throw new ScannerException(
                    RESOURCE_CATEGORY,
                    "Kubernetes API returned a null response for " + RESOURCE_CATEGORY
                            + "; cannot distinguish an empty cluster from an API failure",
                    null);
        }

        if (secretList.getItems() == null) {
            return Collections.emptyList();
        }

        List<SecretSnapshot> results = new ArrayList<>(secretList.getItems().size());
        for (Secret secret : secretList.getItems()) {
            results.add(mapToSnapshot(secret));
        }
        return results;
    }

    private SecretSnapshot mapToSnapshot(Secret k8sSecret) {
        SecretSnapshot snapshot = new SecretSnapshot();
        var metadata = k8sSecret.getMetadata();

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
                    // Only the timestamp string and the name/namespace (not any secret value)
                    // appear in this message.
                    throw new ScannerException(
                            RESOURCE_CATEGORY,
                            "Failed to parse creationTimestamp '"
                                    + metadata.getCreationTimestamp()
                                    + "' for Secret '" + metadata.getNamespace()
                                    + "/" + metadata.getName() + "'",
                            e);
                }
            }
        }

        // Capture the secret type (e.g. "kubernetes.io/service-account-token", "Opaque")
        snapshot.setSecretType(k8sSecret.getType());

        return snapshot;
    }
}
