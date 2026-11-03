package com.kunal.attackpathvisualizer.common.exception;

/** Uniform JSON error body returned by the REST layer. */
public record ApiError(
        String timestamp,
        int status,
        String error,
        String message,
        String path
) {
}