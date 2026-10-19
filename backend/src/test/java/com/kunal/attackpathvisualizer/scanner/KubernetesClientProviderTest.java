package com.kunal.attackpathvisualizer.scanner;

import io.fabric8.kubernetes.api.model.Namespace;
import io.fabric8.kubernetes.api.model.NamespaceList;
import io.fabric8.kubernetes.client.KubernetesClient;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Tag;

@Tag("integration")
public class KubernetesClientProviderTest {

    @Test
    @DisplayName("Should establish connection to Minikube cluster and retrieve active namespaces")
    void shouldConnectToKubernetesAndRetrieveNamespaces() {
        // 1. Initialize the provider with auto-discovered config (~/.kube/config -> Minikube)
        KubernetesClientProvider provider = new KubernetesClientProvider();

        // 2. Obtain the underlying Fabric8 KubernetesClient
        KubernetesClient client = provider.getClient();

        assertNotNull(client, "KubernetesClient instance should not be null");

        // 3. Execute Fabric8 DSL method to fetch all cluster namespaces
        NamespaceList namespaceList = client.namespaces().list();

        // 4. Assert response validity against live cluster
        assertNotNull(namespaceList, "Namespace list returned from cluster should not be null");

        List<Namespace> namespaces = namespaceList.getItems();
        assertNotNull(namespaces, "Namespace items list should not be null");
        assertFalse(namespaces.isEmpty(), "Cluster must contain at least one namespace");

        // 5. Verify presence of essential Kubernetes system namespaces
        List<String> namespaceNames = namespaces.stream()
                .map(ns -> ns.getMetadata().getName())
                .toList();

        assertTrue(namespaceNames.contains("default"), "Discovered namespaces should contain 'default'");
        assertTrue(namespaceNames.contains("kube-system"), "Discovered namespaces should contain 'kube-system'");

        // Optional log output to confirm Minikube discovery in test console
        System.out.println("Discovered " + namespaces.size() + " namespaces from cluster:");
        namespaceNames.forEach(name -> System.out.println(" - " + name));
    }
}
