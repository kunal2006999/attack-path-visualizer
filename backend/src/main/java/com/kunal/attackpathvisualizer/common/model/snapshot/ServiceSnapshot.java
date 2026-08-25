package com.kunal.attackpathvisualizer.common.model.snapshot;

import java.util.Map;

/** Snapshot DTO for a Kubernetes Service. Maps to core.model.Service. */
public class ServiceSnapshot extends ResourceSnapshot {

    private Map<String, String> selector;

    public ServiceSnapshot() {}

    public Map<String, String> getSelector() { return selector; }
    public void setSelector(Map<String, String> selector) { this.selector = selector; }
}
