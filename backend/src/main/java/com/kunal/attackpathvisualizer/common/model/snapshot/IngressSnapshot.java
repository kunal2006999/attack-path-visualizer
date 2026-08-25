package com.kunal.attackpathvisualizer.common.model.snapshot;

/** Snapshot DTO for a Kubernetes Ingress. Maps to core.model.Ingress. */
public class IngressSnapshot extends ResourceSnapshot {

    private String serviceName;

    public IngressSnapshot() {}

    public String getServiceName() { return serviceName; }
    public void setServiceName(String serviceName) { this.serviceName = serviceName; }
}
