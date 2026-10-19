package com.kunal.attackpathvisualizer.scanner;

import io.fabric8.kubernetes.client.KubernetesClient;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link KubernetesClientProvider} constructor guards and accessor.
 * Does not require Minikube.
 */
@ExtendWith(MockitoExtension.class)
class KubernetesClientProviderUnitTest {

    @Mock
    private KubernetesClient mockClient;

    @Test
    void injectionConstructorRejectsNullClient() {
        assertThrows(IllegalArgumentException.class,
                () -> new KubernetesClientProvider(null));
    }

    @Test
    void injectionConstructorAcceptsValidClient() {
        KubernetesClientProvider provider = new KubernetesClientProvider(mockClient);
        assertSame(mockClient, provider.getClient(),
                "getClient() must return the exact client instance that was provided");
    }

    @Test
    void getClientNeverReturnsNull() {
        KubernetesClientProvider provider = new KubernetesClientProvider(mockClient);
        assertNotNull(provider.getClient());
    }
}
