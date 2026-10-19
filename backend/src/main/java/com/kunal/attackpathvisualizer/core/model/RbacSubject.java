package com.kunal.attackpathvisualizer.core.model;

import java.util.List;

/** An RBAC subject. Only ServiceAccount subjects are linked into the graph. */
public class RbacSubject {

    public static final String SERVICE_ACCOUNT = "ServiceAccount";

    private final String kind;
    private final String name;
    private final String namespace;

    public RbacSubject(String kind, String name, String namespace) {
        this.kind = kind;
        this.name = name;
        this.namespace = namespace;
    }

    public static List<RbacSubject> fromServiceAccountNames(List<String> names) {
        if (names == null) {
            return List.of();
        }
        return names.stream()
                .map(n -> new RbacSubject(SERVICE_ACCOUNT, n, null))
                .toList();
    }

    public String getKind() { return kind; }
    public String getName() { return name; }
    public String getNamespace() { return namespace; }

    public boolean isServiceAccount() {
        return SERVICE_ACCOUNT.equalsIgnoreCase(kind);
    }
}