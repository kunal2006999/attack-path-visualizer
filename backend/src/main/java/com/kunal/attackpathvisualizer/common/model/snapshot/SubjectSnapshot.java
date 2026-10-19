package com.kunal.attackpathvisualizer.common.model.snapshot;

public class SubjectSnapshot {
    private String kind;
    private String name;
    private String namespace;

    public SubjectSnapshot() {}

    public static SubjectSnapshot of(String kind, String name, String namespace) {
        SubjectSnapshot s = new SubjectSnapshot();
        s.kind = kind;
        s.name = name;
        s.namespace = namespace;
        return s;
    }

    public String getKind() { return kind; }
    public void setKind(String kind) { this.kind = kind; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getNamespace() { return namespace; }
    public void setNamespace(String namespace) { this.namespace = namespace; }
}
