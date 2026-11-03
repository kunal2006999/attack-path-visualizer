package com.kunal.attackpathvisualizer.security;

import com.kunal.attackpathvisualizer.core.model.Secret;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SecretSensitivityClassifierTest {

    private SecretSensitivityClassifier classifier;

    @BeforeEach
    void setUp() {
        classifier = new SecretSensitivityClassifier();
    }

    private Secret createSecret(
            String name,
            String namespace,
            String type,
            Map<String, String> labels
    ) {
        return new Secret(
                "uid-" + name,
                name,
                namespace,
                labels,
                Map.of(),
                Instant.parse("2026-01-01T00:00:00Z"),
                type
        );
    }

    @Test
    void shouldAssignBaseScoreForOpaqueSecret() {
        Secret secret = createSecret(
                "application-config",
                "default",
                "Opaque",
                Map.of()
        );

        assertEquals(20, classifier.classify(secret));
    }

    @Test
    void shouldScoreTlsSecret() {
        Secret secret = createSecret(
                "web-tls",
                "default",
                "kubernetes.io/tls",
                Map.of()
        );

        assertEquals(35, classifier.classify(secret));
    }

    @Test
    void shouldScoreServiceAccountTokenSecret() {
        Secret secret = createSecret(
                "service-token",
                "default",
                "kubernetes.io/service-account-token",
                Map.of()
        );

        assertEquals(30, classifier.classify(secret));
    }

    @Test
    void shouldAddPointsForSensitiveName() {
        Secret secret = createSecret(
                "database-credentials",
                "default",
                "Opaque",
                Map.of()
        );

        assertEquals(25, classifier.classify(secret));
    }

    @Test
    void shouldAddPointsForSensitiveLabel() {
        Secret secret = createSecret(
                "application-config",
                "default",
                "Opaque",
                Map.of("sensitive", "true")
        );

        assertEquals(25, classifier.classify(secret));
    }

    @Test
    void shouldAddPointsForKubeSystemNamespace() {
        Secret secret = createSecret(
                "application-config",
                "kube-system",
                "Opaque",
                Map.of()
        );

        assertEquals(25, classifier.classify(secret));
    }

    @Test
    void shouldCapScoreAtForty() {
        Secret secret = createSecret(
                "production-database-credentials",
                "kube-system",
                "kubernetes.io/tls",
                Map.of("sensitive", "true")
        );

        assertEquals(40, classifier.classify(secret));
    }

    @Test
    void shouldRejectNullSecret() {
        assertThrows(
                IllegalArgumentException.class,
                () -> classifier.classify(null)
        );
    }
}