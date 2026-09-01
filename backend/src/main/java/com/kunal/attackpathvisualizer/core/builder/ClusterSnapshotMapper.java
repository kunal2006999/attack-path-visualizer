package com.kunal.attackpathvisualizer.core.builder;

import com.kunal.attackpathvisualizer.common.model.snapshot.*;
import com.kunal.attackpathvisualizer.core.model.*;
import com.kunal.attackpathvisualizer.core.relation.RelationshipType;
import com.kunal.attackpathvisualizer.core.relation.ResourceRelationship;

import java.util.List;
import java.util.Map;

@org.springframework.stereotype.Component
public class ClusterSnapshotMapper {

    public Cluster map(ClusterSnapshot snapshot) {

        Cluster cluster = new Cluster(snapshot.getClusterName());

        for (NamespaceSnapshot resource : snapshot.getNamespaces()) {
            cluster.addResource(mapNamespace(resource));
        }

        for (NodeSnapshot resource : snapshot.getNodes()) {
            cluster.addResource(mapNode(resource));
        }

        for (PodSnapshot resource : snapshot.getPods()) {
            cluster.addResource(mapPod(resource));
        }

        for (DeploymentSnapshot resource : snapshot.getDeployments()) {
            cluster.addResource(mapDeployment(resource));
        }

        for (ReplicaSetSnapshot resource : snapshot.getReplicaSets()) {
            cluster.addResource(mapReplicaSet(resource));
        }

        for (ServiceSnapshot resource : snapshot.getServices()) {
            cluster.addResource(mapService(resource));
        }

        for (IngressSnapshot resource : snapshot.getIngresses()) {
            cluster.addResource(mapIngress(resource));
        }

        for (ServiceAccountSnapshot resource : snapshot.getServiceAccounts()) {
            cluster.addResource(mapServiceAccount(resource));
        }

        for (RoleSnapshot resource : snapshot.getRoles()) {
            cluster.addResource(mapRole(resource));
        }

        for (ClusterRoleSnapshot resource : snapshot.getClusterRoles()) {
            cluster.addResource(mapClusterRole(resource));
        }

        for (RoleBindingSnapshot resource : snapshot.getRoleBindings()) {
            cluster.addResource(mapRoleBinding(resource));
        }

        for (ClusterRoleBindingSnapshot resource : snapshot.getClusterRoleBindings()) {
            cluster.addResource(mapClusterRoleBinding(resource));
        }

        for (SecretSnapshot resource : snapshot.getSecrets()) {
            cluster.addResource(mapSecret(resource));
        }

        for (ConfigMapSnapshot resource : snapshot.getConfigMaps()) {
            cluster.addResource(mapConfigMap(resource));
        }

        for (PersistentVolumeSnapshot resource : snapshot.getPersistentVolumes()) {
            cluster.addResource(mapPersistentVolume(resource));
        }

        for (PersistentVolumeClaimSnapshot resource : snapshot.getPersistentVolumeClaims()) {
            cluster.addResource(mapPersistentVolumeClaim(resource));
        }

        buildRelationships(cluster);

        return cluster;
    }

    private Namespace mapNamespace(NamespaceSnapshot resource) {
        return new Namespace(
                resource.getUid(),
                resource.getName(),
                resource.getLabels(),
                resource.getAnnotations(),
                resource.getCreationTimestamp()
        );
    }

    private Node mapNode(NodeSnapshot resource) {
        return new Node(
                resource.getUid(),
                resource.getName(),
                resource.getLabels(),
                resource.getAnnotations(),
                resource.getCreationTimestamp()
        );
    }

    private Pod mapPod(PodSnapshot resource) {
        return new Pod(
                resource.getUid(),
                resource.getName(),
                resource.getNamespace(),
                resource.getLabels(),
                resource.getAnnotations(),
                resource.getCreationTimestamp(),
                resource.getServiceAccountName()
        );
    }

    private Deployment mapDeployment(DeploymentSnapshot resource) {
        return new Deployment(
                resource.getUid(),
                resource.getName(),
                resource.getNamespace(),
                resource.getLabels(),
                resource.getAnnotations(),
                resource.getCreationTimestamp(),
                resource.getReplicas(),
                resource.getSelector()
        );
    }

    private ReplicaSet mapReplicaSet(ReplicaSetSnapshot resource) {
        return new ReplicaSet(
                resource.getUid(),
                resource.getName(),
                resource.getNamespace(),
                resource.getLabels(),
                resource.getAnnotations(),
                resource.getCreationTimestamp(),
                resource.getReplicas(),
                resource.getSelector()
        );
    }

    private Service mapService(ServiceSnapshot resource) {
        return new Service(
                resource.getUid(),
                resource.getName(),
                resource.getNamespace(),
                resource.getLabels(),
                resource.getAnnotations(),
                resource.getCreationTimestamp(),
                resource.getSelector()
        );
    }

    private Ingress mapIngress(IngressSnapshot resource) {
        return new Ingress(
                resource.getUid(),
                resource.getName(),
                resource.getNamespace(),
                resource.getLabels(),
                resource.getAnnotations(),
                resource.getCreationTimestamp(),
                resource.getServiceName()
        );
    }

    private ServiceAccount mapServiceAccount(ServiceAccountSnapshot resource) {
        return new ServiceAccount(
                resource.getUid(),
                resource.getName(),
                resource.getNamespace(),
                resource.getLabels(),
                resource.getAnnotations(),
                resource.getCreationTimestamp()
        );
    }

    private Role mapRole(RoleSnapshot resource) {
        return new Role(
                resource.getUid(),
                resource.getName(),
                resource.getNamespace(),
                resource.getLabels(),
                resource.getAnnotations(),
                resource.getCreationTimestamp(),
                mapRules(resource.getRules())
        );
    }

    private ClusterRole mapClusterRole(ClusterRoleSnapshot resource) {
        return new ClusterRole(
                resource.getUid(),
                resource.getName(),
                resource.getLabels(),
                resource.getAnnotations(),
                resource.getCreationTimestamp(),
                mapRules(resource.getRules())
        );
    }

    private RoleBinding mapRoleBinding(RoleBindingSnapshot resource) {
        return new RoleBinding(
                resource.getUid(),
                resource.getName(),
                resource.getNamespace(),
                resource.getLabels(),
                resource.getAnnotations(),
                resource.getCreationTimestamp(),
                resource.getSubjectNames(),
                resource.getRoleName()
        );
    }

    private ClusterRoleBinding mapClusterRoleBinding(
            ClusterRoleBindingSnapshot resource) {

        return new ClusterRoleBinding(
                resource.getUid(),
                resource.getName(),
                resource.getLabels(),
                resource.getAnnotations(),
                resource.getCreationTimestamp(),
                resource.getSubjectNames(),
                resource.getClusterRoleName()
        );
    }

    private Secret mapSecret(SecretSnapshot resource) {
        return new Secret(
                resource.getUid(),
                resource.getName(),
                resource.getNamespace(),
                resource.getLabels(),
                resource.getAnnotations(),
                resource.getCreationTimestamp(),
                resource.getSecretType()
        );
    }

    private ConfigMap mapConfigMap(ConfigMapSnapshot resource) {
        return new ConfigMap(
                resource.getUid(),
                resource.getName(),
                resource.getNamespace(),
                resource.getLabels(),
                resource.getAnnotations(),
                resource.getCreationTimestamp()
        );
    }

    private PersistentVolume mapPersistentVolume(
            PersistentVolumeSnapshot resource) {

        return new PersistentVolume(
                resource.getUid(),
                resource.getName(),
                resource.getLabels(),
                resource.getAnnotations(),
                resource.getCreationTimestamp(),
                resource.getStorageClassName()
        );
    }

    private PersistentVolumeClaim mapPersistentVolumeClaim(
            PersistentVolumeClaimSnapshot resource) {

        return new PersistentVolumeClaim(
                resource.getUid(),
                resource.getName(),
                resource.getNamespace(),
                resource.getLabels(),
                resource.getAnnotations(),
                resource.getCreationTimestamp(),
                resource.getVolumeName(),
                resource.getStorageClassName()
        );
    }

    private List<RbacRule> mapRules(List<RbacRuleSnapshot> rules) {

        return rules.stream()
                .map(rule -> new RbacRule(
                        rule.getApiGroups(),
                        rule.getResources(),
                        rule.getVerbs(),
                        rule.getResourceNames()
                ))
                .toList();
    }

    private void buildRelationships(Cluster cluster) {

        Map<String, KubernetesResource> resourcesByUid =
                cluster.getResources()
                        .stream()
                        .collect(java.util.stream.Collectors.toMap(
                                KubernetesResource::getUid,
                                resource -> resource
                        ));

        /*
         * Pod → ServiceAccount
         */
        for (KubernetesResource resource : cluster.getResources()) {

            if (resource instanceof Pod pod
                    && pod.getServiceAccountName() != null) {

                ServiceAccount serviceAccount =
                        findByNameAndNamespace(
                                cluster,
                                pod.getServiceAccountName(),
                                pod.getNamespace(),
                                ServiceAccount.class
                        );

                if (serviceAccount != null) {

                    cluster.addRelationship(
                            new ResourceRelationship(
                                    pod,
                                    serviceAccount,
                                    RelationshipType.USES
                            )
                    );
                }
            }
        }

        /*
         * ServiceAccount → RoleBinding
         * RoleBinding → Role
         */
        for (KubernetesResource resource : cluster.getResources()) {

            if (resource instanceof RoleBinding binding) {

                if (binding.getSubjectNames() != null) {
                    for (String subjectName : binding.getSubjectNames()) {
                        ServiceAccount serviceAccount =
                                findByNameAndNamespace(
                                        cluster,
                                        subjectName,
                                        binding.getNamespace(),
                                        ServiceAccount.class
                                );

                        if (serviceAccount != null) {
                            cluster.addRelationship(
                                    new ResourceRelationship(
                                            serviceAccount,
                                            binding,
                                            RelationshipType.HAS_BINDING
                                    )
                            );
                        }
                    }
                }

                Role role =
                        findByNameAndNamespace(
                                cluster,
                                binding.getRoleName(),
                                binding.getNamespace(),
                                Role.class
                        );

                if (role != null) {

                    cluster.addRelationship(
                            new ResourceRelationship(
                                    binding,
                                    role,
                                    RelationshipType.GRANTS
                            )
                    );
                }

                /*
                 * Role → Secret
                 *
                 * We inspect the RBAC rules and determine whether
                 * the Role grants access to Secrets.
                 */
                if (role != null) {

                    for (RbacRule rule : role.getRules()) {

                        boolean canAccessSecrets =
                                rule.getResources().contains("secrets")
                                        && (rule.getVerbs().contains("get")
                                        || rule.getVerbs().contains("*"));

                        if (canAccessSecrets) {

                            for (KubernetesResource target :
                                    cluster.getResources()) {

                                if (target instanceof Secret
                                        && java.util.Objects.equals(target.getNamespace(), role.getNamespace())) {

                                    cluster.addRelationship(
                                            new ResourceRelationship(
                                                    role,
                                                    target,
                                                    RelationshipType.CAN_ACCESS
                                            )
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        /*
         * Service → Pod
         */
        for (KubernetesResource resource : cluster.getResources()) {

            if (resource instanceof Service service) {

                for (KubernetesResource target :
                        cluster.getResources()) {

                    if (target instanceof Pod pod
                            && pod.getNamespace()
                            .equals(service.getNamespace())
                            && matchesSelector(
                            service.getSelector(),
                            pod.getLabels())) {

                        cluster.addRelationship(
                                new ResourceRelationship(
                                        service,
                                        pod,
                                        RelationshipType.SELECTS
                                )
                        );
                    }
                }
            }
        }

        /*
         * Ingress → Service
         */
        for (KubernetesResource resource : cluster.getResources()) {

            if (resource instanceof Ingress ingress) {

                Service service =
                        findByNameAndNamespace(
                                cluster,
                                ingress.getServiceName(),
                                ingress.getNamespace(),
                                Service.class
                        );

                if (service != null) {

                    cluster.addRelationship(
                            new ResourceRelationship(
                                    ingress,
                                    service,
                                    RelationshipType.ROUTES_TO
                            )
                    );
                }
            }
        }

        /*
         * PVC → PV
         */
        for (KubernetesResource resource : cluster.getResources()) {

            if (resource instanceof PersistentVolumeClaim pvc
                    && pvc.getVolumeName() != null) {

                PersistentVolume pv =
                        findByNameAndNamespace(
                                cluster,
                                pvc.getVolumeName(),
                                null,
                                PersistentVolume.class
                        );

                if (pv != null) {

                    cluster.addRelationship(
                            new ResourceRelationship(
                                    pvc,
                                    pv,
                                    RelationshipType.DEPENDS_ON
                            )
                    );
                }
            }
        }
        for (KubernetesResource resource : cluster.getResources()) {
            if (resource instanceof ClusterRoleBinding binding) {
                if (binding.getSubjectNames() != null) {
                    for (String subjectName : binding.getSubjectNames()) {
                        ServiceAccount serviceAccount = findByNameAndNamespace(
                                cluster,
                                subjectName,
                                binding.getNamespace(),
                                ServiceAccount.class
                        );

                        if (serviceAccount != null) {
                            cluster.addRelationship(new ResourceRelationship(
                                    serviceAccount,
                                    binding,
                                    RelationshipType.HAS_BINDING
                            ));
                        }
                    }
                }

                ClusterRole clusterRole = findByNameAndNamespace(
                        cluster,
                        binding.getClusterRoleName(),
                        null,
                        ClusterRole.class
                );

                if (clusterRole != null) {
                    cluster.addRelationship(new ResourceRelationship(
                            binding,
                            clusterRole,
                            RelationshipType.GRANTS
                    ));

                    for (RbacRule rule : clusterRole.getRules()) {
                        boolean canAccessSecrets = rule.getResources().contains("secrets")
                                && (rule.getVerbs().contains("get") || rule.getVerbs().contains("*") || rule.getResources().contains("*"));

                        if (canAccessSecrets || rule.getResources().contains("*")) {
                            for (KubernetesResource target : cluster.getResources()) {
                                if (target instanceof Secret) {
                                    cluster.addRelationship(new ResourceRelationship(
                                            clusterRole,
                                            target,
                                            RelationshipType.CAN_ACCESS
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private <T extends KubernetesResource> T findByNameAndNamespace(
            Cluster cluster,
            String name,
            String namespace,
            Class<T> type) {

        return cluster.getResources()
                .stream()
                .filter(type::isInstance)
                .map(type::cast)
                .filter(resource ->
                        resource.getName().equals(name)
                                && java.util.Objects.equals(
                                resource.getNamespace(),
                                namespace
                        )
                )
                .findFirst()
                .orElse(null);
    }

    private boolean matchesSelector(
            Map<String, String> selector,
            Map<String, String> labels) {

        if (selector == null || selector.isEmpty()) {
            return false;
        }

        if (labels == null || labels.isEmpty()) {
            return false;
        }

        return selector.entrySet()
                .stream()
                .allMatch(entry ->
                        entry.getValue().equals(
                                labels.get(entry.getKey())
                        )
                );
    }
}