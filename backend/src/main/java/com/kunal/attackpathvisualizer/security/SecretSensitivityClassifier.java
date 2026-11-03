package com.kunal.attackpathvisualizer.security;

import com.kunal.attackpathvisualizer.core.model.Secret;
import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.Map;

@Component
public class SecretSensitivityClassifier {

    private static final int MAX_SENSITIVITY = 40;

    public int classify(Secret secret) {
        if (secret == null) {
            throw new IllegalArgumentException(
                    "Secret cannot be null"
            );
        }

        int score = getBaseScore(secret.getSecretType());

        score += scoreSensitiveLabels(secret.getLabels());
        score += scoreSensitiveName(secret.getName());
        score += scoreNamespace(secret.getNamespace());

        return Math.min(score, MAX_SENSITIVITY);
    }

    private int getBaseScore(String secretType) {
        if (secretType == null) {
            return 20;
        }

        return switch (secretType.toLowerCase(Locale.ROOT)) {
            case "kubernetes.io/tls" -> 30;
            case "kubernetes.io/dockerconfigjson",
                 "kubernetes.io/dockercfg" -> 30;
            case "kubernetes.io/service-account-token" -> 25;
            default -> 20;
        };
    }

    private int scoreSensitiveLabels(Map<String, String> labels) {
        if (labels == null || labels.isEmpty()) {
            return 0;
        }

        for (Map.Entry<String, String> entry : labels.entrySet()) {
            String key = normalize(entry.getKey());
            String value = normalize(entry.getValue());

            if (key.contains("sensitive")
                    || key.contains("critical")
                    || key.contains("confidential")) {
                return 5;
            }

            if ((key.equals("security-level")
                    || key.equals("security_level"))
                    && (value.equals("high")
                    || value.equals("critical"))) {
                return 5;
            }
        }

        return 0;
    }

    private int scoreSensitiveName(String name) {
        String normalized = normalize(name);

        if (normalized.isBlank()) {
            return 0;
        }

        String[] sensitiveTerms = {
                "prod",
                "production",
                "credential",
                "credentials",
                "password",
                "token",
                "private-key",
                "private_key",
                "privatekey",
                "api-key",
                "api_key",
                "apikey",
                "database",
                "db-secret",
                "tls"
        };

        for (String term : sensitiveTerms) {
            if (normalized.contains(term)) {
                return 5;
            }
        }

        return 0;
    }

    private int scoreNamespace(String namespace) {
        if (namespace == null) {
            return 0;
        }

        if ("kube-system".equalsIgnoreCase(namespace.trim())) {
            return 5;
        }

        return 0;
    }

    private String normalize(String value) {
        return value == null
                ? ""
                : value.trim().toLowerCase(Locale.ROOT);
    }
}