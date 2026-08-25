package com.kunal.attackpathvisualizer.common.model.snapshot;

/**
 * Snapshot DTO for a Kubernetes Secret.
 * Secret data values are deliberately excluded from this DTO.
 * Maps to core.model.Secret.
 */
public class SecretSnapshot extends ResourceSnapshot {

    private String secretType;

    public SecretSnapshot() {}

    public String getSecretType() { return secretType; }
    public void setSecretType(String secretType) { this.secretType = secretType; }
}
