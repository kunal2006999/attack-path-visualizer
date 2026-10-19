package com.kunal.attackpathvisualizer.scanner;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link ScannerException}.
 */
class ScannerExceptionTest {

    @Test
    void storesResourceCategory() {
        ScannerException ex = new ScannerException("Pods", "something went wrong", null);
        assertEquals("Pods", ex.getResourceCategory());
    }

    @Test
    void storesMessage() {
        ScannerException ex = new ScannerException("Pods", "something went wrong", null);
        assertEquals("something went wrong", ex.getMessage());
    }

    @Test
    void storesCause() {
        RuntimeException cause = new RuntimeException("original");
        ScannerException ex = new ScannerException("Namespaces", "wrapped", cause);
        assertSame(cause, ex.getCause());
    }

    @Test
    void isRuntimeException() {
        ScannerException ex = new ScannerException("Secrets", "msg", null);
        assertInstanceOf(RuntimeException.class, ex);
    }

    @Test
    void resourceCategoryIsNeverNull() {
        ScannerException ex = new ScannerException("ClusterRoles", "msg", null);
        assertNotNull(ex.getResourceCategory());
    }
}
