package com.kunal.attackpathvisualizer.scanner;

/**
 * Thrown when a Kubernetes scanner fails to collect resources from the API server.
 *
 * <p>Distinguishes infrastructure / API failures (connection refused, timeout, RBAC denial)
 * from programming errors so callers can apply appropriate recovery logic.
 *
 * <p>The {@code resourceCategory} identifies which resource type was being scanned
 * (e.g. "Pods", "Secrets") so the caller receives an actionable error message without
 * any sensitive data.
 */
public class ScannerException extends RuntimeException {

    private final String resourceCategory;

    /**
     * @param resourceCategory human-readable name of the resource category being scanned
     *                         (e.g. {@code "Pods"}, {@code "ClusterRoles"})
     * @param message          description of what went wrong
     * @param cause            the underlying exception from Fabric8 or the JDK
     */
    public ScannerException(String resourceCategory, String message, Throwable cause) {
        super(message, cause);
        this.resourceCategory = resourceCategory;
    }

    /**
     * Returns the resource category that was being scanned when this exception was thrown.
     * Never {@code null}.
     */
    public String getResourceCategory() {
        return resourceCategory;
    }
}
