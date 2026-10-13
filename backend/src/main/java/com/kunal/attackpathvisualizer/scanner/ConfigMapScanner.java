package com.kunal.attackpathvisualizer.scanner;

import com.kunal.attackpathvisualizer.common.model.snapshot.ConfigMapSnapshot;
import io.fabric8.kubernetes.api.model.ConfigMap;
import io.fabric8.kubernetes.api.model.ConfigMapList;
import io.fabric8.kubernetes.client.KubernetesClient;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Scans all Kubernetes ConfigMaps across all namespaces and maps them to
 * {@link ConfigMapSnapshot} DTOs.
 */
public class ConfigMapScanner {

    private final KubernetesClient client;

    public ConfigMapScanner(KubernetesClient client) {
        this.client = client;
    }

    public List<ConfigMapSnapshot> scan() {
        ConfigMapList configMapList = client.configMaps().inAnyNamespace().list();

        if (configMapList == null || configMapList.getItems() == null) {
            return Collections.emptyList();
        }

        return configMapList.getItems().stream()
                .map(this::mapToSnapshot)
                .collect(Collectors.toList());
    }

    private ConfigMapSnapshot mapToSnapshot(ConfigMap k8sConfigMap) {
        ConfigMapSnapshot snapshot = new ConfigMapSnapshot();
        var metadata = k8sConfigMap.getMetadata();

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
