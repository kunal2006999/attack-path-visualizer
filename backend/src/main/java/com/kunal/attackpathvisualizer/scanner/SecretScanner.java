package com.kunal.attackpathvisualizer.scanner;

import com.kunal.attackpathvisualizer.common.model.snapshot.SecretSnapshot;
import io.fabric8.kubernetes.api.model.Secret;
import io.fabric8.kubernetes.api.model.SecretList;
import io.fabric8.kubernetes.client.KubernetesClient;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Scans all Kubernetes Secrets across all namespaces and maps them to {@link SecretSnapshot} DTOs.
 * <p>
 * NOTE: Secret {@code data} values are intentionally NOT captured — only metadata and the
 * secret type are recorded, to avoid handling sensitive material in memory.
 */
public class SecretScanner {

    private final KubernetesClient client;

    public SecretScanner(KubernetesClient client) {
        this.client = client;
    }

    public List<SecretSnapshot> scan() {
        SecretList secretList = client.secrets().inAnyNamespace().list();

        if (secretList == null || secretList.getItems() == null) {
            return Collections.emptyList();
        }

        return secretList.getItems().stream()
                .map(this::mapToSnapshot)
                .collect(Collectors.toList());
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
                Instant timestamp = Instant.from(
                        DateTimeFormatter.ISO_OFFSET_DATE_TIME.parse(
                                metadata.getCreationTimestamp()
                        )
                );
                snapshot.setCreationTimestamp(timestamp);
            }
        }

        // Capture the secret type (e.g. "kubernetes.io/service-account-token", "Opaque")
        snapshot.setSecretType(k8sSecret.getType());

        return snapshot;
    }
}
