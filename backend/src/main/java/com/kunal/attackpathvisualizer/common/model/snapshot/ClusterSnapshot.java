package com.kunal.attackpathvisualizer.common.model.snapshot;

import java.util.List;

/**
 * Top-level snapshot DTO representing the entire state of one Kubernetes cluster.
 * Does NOT extend ResourceSnapshot - a cluster is not itself a Kubernetes API resource.
 */
public class ClusterSnapshot {

    private String clusterName;

    private List<NamespaceSnapshot> namespaces;
    private List<NodeSnapshot> nodes;
    private List<PodSnapshot> pods;
    private List<DeploymentSnapshot> deployments;
    private List<ReplicaSetSnapshot> replicaSets;
    private List<ServiceSnapshot> services;
    private List<IngressSnapshot> ingresses;
    private List<ServiceAccountSnapshot> serviceAccounts;
    private List<RoleSnapshot> roles;
    private List<ClusterRoleSnapshot> clusterRoles;
    private List<RoleBindingSnapshot> roleBindings;
    private List<ClusterRoleBindingSnapshot> clusterRoleBindings;
    private List<SecretSnapshot> secrets;
    private List<ConfigMapSnapshot> configMaps;
    private List<PersistentVolumeSnapshot> persistentVolumes;
    private List<PersistentVolumeClaimSnapshot> persistentVolumeClaims;

    public ClusterSnapshot() {}

    public String getClusterName() { return clusterName; }
    public void setClusterName(String clusterName) { this.clusterName = clusterName; }

    public List<NamespaceSnapshot> getNamespaces() { return namespaces; }
    public void setNamespaces(List<NamespaceSnapshot> namespaces) { this.namespaces = namespaces; }

    public List<NodeSnapshot> getNodes() { return nodes; }
    public void setNodes(List<NodeSnapshot> nodes) { this.nodes = nodes; }

    public List<PodSnapshot> getPods() { return pods; }
    public void setPods(List<PodSnapshot> pods) { this.pods = pods; }

    public List<DeploymentSnapshot> getDeployments() { return deployments; }
    public void setDeployments(List<DeploymentSnapshot> deployments) { this.deployments = deployments; }

    public List<ReplicaSetSnapshot> getReplicaSets() { return replicaSets; }
    public void setReplicaSets(List<ReplicaSetSnapshot> replicaSets) { this.replicaSets = replicaSets; }

    public List<ServiceSnapshot> getServices() { return services; }
    public void setServices(List<ServiceSnapshot> services) { this.services = services; }

    public List<IngressSnapshot> getIngresses() { return ingresses; }
    public void setIngresses(List<IngressSnapshot> ingresses) { this.ingresses = ingresses; }

    public List<ServiceAccountSnapshot> getServiceAccounts() { return serviceAccounts; }
    public void setServiceAccounts(List<ServiceAccountSnapshot> serviceAccounts) { this.serviceAccounts = serviceAccounts; }

    public List<RoleSnapshot> getRoles() { return roles; }
    public void setRoles(List<RoleSnapshot> roles) { this.roles = roles; }

    public List<ClusterRoleSnapshot> getClusterRoles() { return clusterRoles; }
    public void setClusterRoles(List<ClusterRoleSnapshot> clusterRoles) { this.clusterRoles = clusterRoles; }

    public List<RoleBindingSnapshot> getRoleBindings() { return roleBindings; }
    public void setRoleBindings(List<RoleBindingSnapshot> roleBindings) { this.roleBindings = roleBindings; }

    public List<ClusterRoleBindingSnapshot> getClusterRoleBindings() { return clusterRoleBindings; }
    public void setClusterRoleBindings(List<ClusterRoleBindingSnapshot> clusterRoleBindings) { this.clusterRoleBindings = clusterRoleBindings; }

    public List<SecretSnapshot> getSecrets() { return secrets; }
    public void setSecrets(List<SecretSnapshot> secrets) { this.secrets = secrets; }

    public List<ConfigMapSnapshot> getConfigMaps() { return configMaps; }
    public void setConfigMaps(List<ConfigMapSnapshot> configMaps) { this.configMaps = configMaps; }

    public List<PersistentVolumeSnapshot> getPersistentVolumes() { return persistentVolumes; }
    public void setPersistentVolumes(List<PersistentVolumeSnapshot> persistentVolumes) { this.persistentVolumes = persistentVolumes; }

    public List<PersistentVolumeClaimSnapshot> getPersistentVolumeClaims() { return persistentVolumeClaims; }
    public void setPersistentVolumeClaims(List<PersistentVolumeClaimSnapshot> persistentVolumeClaims) { this.persistentVolumeClaims = persistentVolumeClaims; }
}
