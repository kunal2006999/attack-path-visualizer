package com.kunal.attackpathvisualizer.scanner;
import io.fabric8.kubernetes.client.Config;
import io.fabric8.kubernetes.client.ConfigBuilder;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientBuilder;

public class KubernetesClientProvider {

    private final KubernetesClient client;

    public KubernetesClientProvider() {
        this.client = new KubernetesClientBuilder().build();
    }

    public KubernetesClientProvider(KubernetesClient client) {
        this.client = client;
    }

    public KubernetesClient getClient() {
        return this.client;
    }
}
