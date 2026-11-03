package com.kunal.attackpathvisualizer.common.exception;

/** Thrown when a submitted cluster snapshot is missing, empty or fails validation. */
public class InvalidClusterSnapshotException extends RuntimeException {

    public InvalidClusterSnapshotException(String message) {
        super(message);
    }

    public InvalidClusterSnapshotException(String message, Throwable cause) {
        super(message, cause);
    }
}