package com.kunal.attackpathvisualizer.scanner;

import io.fabric8.kubernetes.api.model.NamespaceList;
import io.fabric8.kubernetes.api.model.ObjectMeta;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientException;
import io.fabric8.kubernetes.client.dsl.NonNamespaceOperation;
import io.fabric8.kubernetes.client.dsl.Resource;
import io.fabric8.kubernetes.api.model.Namespace;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link NamespaceScanner} error handling.
 * Does not require Minikube.
 */
@ExtendWith(MockitoExtension.class)
class NamespaceScannerErrorHandlingTest {

    @Mock
    private KubernetesClient client;

    @Mock
    @SuppressWarnings("rawtypes")
    private NonNamespaceOperation namespacesOp;

    // ── Constructor guard ────────────────────────────────────────────────────

    @Test
    void constructorRejectsNullClient() {
        assertThrows(IllegalArgumentException.class, () -> new NamespaceScanner(null));
    }

    // ── API failure propagation ──────────────────────────────────────────────

    @Test
    @SuppressWarnings("unchecked")
    void scanThrowsScannerExceptionOnKubernetesClientException() {
        when(client.namespaces()).thenReturn(namespacesOp);
        when(namespacesOp.list()).thenThrow(new KubernetesClientException("connection refused"));

        NamespaceScanner scanner = new NamespaceScanner(client);

        ScannerException ex = assertThrows(ScannerException.class, scanner::scan);

        assertEquals("Namespaces", ex.getResourceCategory());
        assertNotNull(ex.getMessage());
        assertInstanceOf(KubernetesClientException.class, ex.getCause());
    }

    // ── Null API response ────────────────────────────────────────────────────

    @Test
    @SuppressWarnings("unchecked")
    void scanThrowsScannerExceptionWhenApiReturnsNullList() {
        when(client.namespaces()).thenReturn(namespacesOp);
        when(namespacesOp.list()).thenReturn(null);

        NamespaceScanner scanner = new NamespaceScanner(client);

        ScannerException ex = assertThrows(ScannerException.class, scanner::scan);

        assertEquals("Namespaces", ex.getResourceCategory());
        assertTrue(ex.getMessage().contains("null response"),
                "Expected 'null response' in message, got: " + ex.getMessage());
    }

    // ── Invalid timestamp ────────────────────────────────────────────────────

    @Test
    @SuppressWarnings("unchecked")
    void scanThrowsScannerExceptionOnMalformedTimestamp() {
        Namespace ns = new Namespace();
        ObjectMeta meta = new ObjectMeta();
        meta.setUid("uid-1");
        meta.setName("bad-ts-ns");
        meta.setCreationTimestamp("NOT-A-VALID-RFC3339-TIMESTAMP");
        ns.setMetadata(meta);

        NamespaceList list = new NamespaceList();
        list.setItems(List.of(ns));

        when(client.namespaces()).thenReturn(namespacesOp);
        when(namespacesOp.list()).thenReturn(list);

        NamespaceScanner scanner = new NamespaceScanner(client);

        ScannerException ex = assertThrows(ScannerException.class, scanner::scan);

        assertEquals("Namespaces", ex.getResourceCategory());
        assertTrue(ex.getMessage().contains("NOT-A-VALID-RFC3339-TIMESTAMP"),
                "Expected malformed timestamp in message, got: " + ex.getMessage());
    }

    // ── Empty items list is valid ────────────────────────────────────────────

    @Test
    @SuppressWarnings("unchecked")
    void scanReturnsEmptyListWhenClusterHasNoNamespaces() {
        NamespaceList list = new NamespaceList();
        list.setItems(List.of());

        when(client.namespaces()).thenReturn(namespacesOp);
        when(namespacesOp.list()).thenReturn(list);

        NamespaceScanner scanner = new NamespaceScanner(client);

        List<?> result = scanner.scan();

        assertNotNull(result);
        assertTrue(result.isEmpty());
    }
}
