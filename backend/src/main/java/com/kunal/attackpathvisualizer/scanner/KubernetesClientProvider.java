package com.kunal.attackpathvisualizer.scanner;

import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientBuilder;

/**
 * Thin wrapper around {@link KubernetesClient} to provide a consistent construction point.
 *
 * <p>The default no-arg constructor auto-discovers cluster configuration from
 * {@code ~/.kube/config} or in-cluster service account credentials (KUBERNETES_SERVICE_HOST).
 * The secondary constructor accepts an already-constructed client, primarily for testing.
 */
public class KubernetesClientProvider {

    private final KubernetesClient client;

    /** Builds a client using auto-discovered configuration (kubeconfig / in-cluster). */
    public KubernetesClientProvider() {
        this.client = new KubernetesClientBuilder().build();
    }

    /**
     * Accepts a pre-constructed client. The caller retains responsibility for closing it.
     *
     * @param client a non-null, already-initialised {@link KubernetesClient}
     * @throws IllegalArgumentException if {@code client} is {@code null}
     */
    public KubernetesClientProvider(KubernetesClient client) {
        if (client == null) {
            throw new IllegalArgumentException("KubernetesClient must not be null");
        }
        this.client = client;
    }

    /** Returns the underlying {@link KubernetesClient}. Never {@code null}. */
    public KubernetesClient getClient() {
        return this.client;
    }
}
