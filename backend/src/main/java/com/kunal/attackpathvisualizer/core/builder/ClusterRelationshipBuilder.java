package com.kunal.attackpathvisualizer.core.builder;

import com.kunal.attackpathvisualizer.core.enums.ResourceType;
import com.kunal.attackpathvisualizer.core.model.*;
import com.kunal.attackpathvisualizer.core.relation.RelationshipType;
import com.kunal.attackpathvisualizer.core.relation.ResourceRelationship;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Builds relationships between core resources.
 *
 * Scope rules:
 *  - Role grants apply only to Secrets in the Role's namespace (edge Role -> Secret).
 *  - ClusterRole grants are emitted from the BINDING (not the shared ClusterRole node),
 *    limited to the RoleBinding's namespace or to all namespaces for a ClusterRoleBinding.
 *  - Only ServiceAccount subjects are linked; User/Group subjects are ignored.
 *  - Unresolved references produce no relationship.
 *
 * Known limitations: no subresources, nonResourceURLs, aggregated ClusterRoles,
 * impersonation, or label/field selectors.
 */
public class ClusterRelationshipBuilder {

    /** list/watch return Secret contents in Kubernetes, so they count as read access. */
    private static final Set<String> SECRET_READ_VERBS = Set.of("get", "list", "watch", "*");

    public void build(Cluster cluster) {
        List<KubernetesResource> resources = cluster.getResources();
        Index index = new Index(resources);

        for (KubernetesResource resource : resources) {
            if (resource instanceof Pod pod) {
                linkPod(cluster, index, pod);
            } else if (resource instanceof RoleBinding rb) {
                linkRoleBinding(cluster, index, resources, rb);
            } else if (resource instanceof ClusterRoleBinding crb) {
                linkClusterRoleBinding(cluster, index, resources, crb);
            } else if (resource instanceof Service service) {
                linkService(cluster, resources, service);
            } else if (resource instanceof Ingress ingress) {
                linkIngress(cluster, index, ingress);
            } else if (resource instanceof PersistentVolumeClaim pvc) {
                linkPvc(cluster, index, pvc);
            }
        }
    }

    private void linkPod(Cluster cluster, Index index, Pod pod) {
        if (isBlank(pod.getServiceAccountName()) || pod.getNamespace() == null) {
            return;
        }
        ServiceAccount sa = index.find(ResourceType.SERVICE_ACCOUNT, ServiceAccount.class,
                pod.getNamespace(), pod.getServiceAccountName());
        add(cluster, pod, sa, RelationshipType.USES);
    }

    private void linkRoleBinding(Cluster cluster, Index index,
                                 List<KubernetesResource> resources, RoleBinding rb) {
        if (rb.getNamespace() == null) {
            return;
        }
        linkSubjects(cluster, index, rb, rb.getSubjects(), rb.getNamespace());

        if ("ClusterRole".equals(rb.getRoleKind())) {
            ClusterRole clusterRole = index.find(ResourceType.CLUSTER_ROLE, ClusterRole.class,
                    null, rb.getRoleName());
            if (clusterRole == null) {
                return;
            }
            add(cluster, rb, clusterRole, RelationshipType.GRANTS);
            // Scoped to the binding's namespace, emitted from the binding.
            grantSecretAccess(cluster, resources, rb, clusterRole.getRules(), rb.getNamespace(), false);
        } else {
            Role role = index.find(ResourceType.ROLE, Role.class, rb.getNamespace(), rb.getRoleName());
            if (role == null) {
                return;
            }
            add(cluster, rb, role, RelationshipType.GRANTS);
            grantSecretAccess(cluster, resources, role, role.getRules(), role.getNamespace(), false);
        }
    }

    private void linkClusterRoleBinding(Cluster cluster, Index index,
                                        List<KubernetesResource> resources, ClusterRoleBinding crb) {
        // Subjects without an explicit namespace cannot be resolved (defaultNamespace = null).
        linkSubjects(cluster, index, crb, crb.getSubjects(), null);

        ClusterRole clusterRole = index.find(ResourceType.CLUSTER_ROLE, ClusterRole.class,
                null, crb.getClusterRoleName());
        if (clusterRole == null) {
            return;
        }
        add(cluster, crb, clusterRole, RelationshipType.GRANTS);
        grantSecretAccess(cluster, resources, crb, clusterRole.getRules(), null, true);
    }

    private void linkSubjects(Cluster cluster, Index index, KubernetesResource binding,
                              List<RbacSubject> subjects, String defaultNamespace) {
        for (RbacSubject subject : subjects) {
            if (!subject.isServiceAccount() || isBlank(subject.getName())) {
                continue;
            }
            String ns = subject.getNamespace() != null ? subject.getNamespace() : defaultNamespace;
            if (ns == null) {
                continue;
            }
            ServiceAccount sa = index.find(ResourceType.SERVICE_ACCOUNT, ServiceAccount.class,
                    ns, subject.getName());
            add(cluster, sa, binding, RelationshipType.HAS_BINDING);
        }
    }

    private void grantSecretAccess(Cluster cluster, List<KubernetesResource> resources,
                                   KubernetesResource source, List<RbacRule> rules,
                                   String namespace, boolean allNamespaces) {
        for (KubernetesResource candidate : resources) {
            if (!(candidate instanceof Secret secret)) {
                continue;
            }
            if (!allNamespaces && !Objects.equals(namespace, secret.getNamespace())) {
                continue;
            }
            if (anyRuleGrantsSecretRead(rules, secret)) {
                add(cluster, source, secret, RelationshipType.CAN_ACCESS);
            }
        }
    }

    static boolean anyRuleGrantsSecretRead(List<RbacRule> rules, Secret secret) {
        if (rules == null) {
            return false;
        }
        for (RbacRule rule : rules) {
            if (rule == null) {
                continue;
            }
            List<String> groups = safe(rule.getApiGroups());
            List<String> resources = safe(rule.getResources());
            List<String> verbs = safe(rule.getVerbs());
            List<String> names = safe(rule.getResourceNames());

            boolean coreGroup = groups.contains("") || groups.contains("*");
            boolean resourceMatches = resources.contains("secrets") || resources.contains("*");
            boolean verbMatches = verbs.stream().anyMatch(SECRET_READ_VERBS::contains);
            boolean nameMatches = names.isEmpty() || names.contains(secret.getName());

            if (coreGroup && resourceMatches && verbMatches && nameMatches) {
                return true;
            }
        }
        return false;
    }

    private void linkService(Cluster cluster, List<KubernetesResource> resources, Service service) {
        if (service.getNamespace() == null) {
            return;
        }
        for (KubernetesResource candidate : resources) {
            if (candidate instanceof Pod pod
                    && service.getNamespace().equals(pod.getNamespace())
                    && matchesSelector(service.getSelector(), pod.getLabels())) {
                add(cluster, service, pod, RelationshipType.SELECTS);
            }
        }
    }

    private void linkIngress(Cluster cluster, Index index, Ingress ingress) {
        if (ingress.getNamespace() == null || isBlank(ingress.getServiceName())) {
            return;
        }
        Service service = index.find(ResourceType.SERVICE, Service.class,
                ingress.getNamespace(), ingress.getServiceName());
        add(cluster, ingress, service, RelationshipType.ROUTES_TO);
    }

    private void linkPvc(Cluster cluster, Index index, PersistentVolumeClaim pvc) {
        if (isBlank(pvc.getVolumeName())) {
            return;
        }
        PersistentVolume pv = index.find(ResourceType.PERSISTENT_VOLUME, PersistentVolume.class,
                null, pvc.getVolumeName());
        add(cluster, pvc, pv, RelationshipType.DEPENDS_ON);
    }

    private static boolean matchesSelector(Map<String, String> selector, Map<String, String> labels) {
        if (selector == null || selector.isEmpty() || labels == null || labels.isEmpty()) {
            return false;
        }
        return selector.entrySet().stream()
                .allMatch(e -> e.getValue() != null && e.getValue().equals(labels.get(e.getKey())));
    }

    private static void add(Cluster cluster, KubernetesResource source,
                            KubernetesResource target, RelationshipType type) {
        if (source != null && target != null) {
            cluster.addRelationship(new ResourceRelationship(source, target, type));
        }
    }

    private static <T> List<T> safe(List<T> list) {
        return list == null ? Collections.emptyList() : list;
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    /** Lookup index keyed by type + namespace + name. */
    private static final class Index {
        private final Map<String, KubernetesResource> byKey = new HashMap<>();

        Index(List<KubernetesResource> resources) {
            for (KubernetesResource r : resources) {
                if (r.getName() != null) {
                    byKey.putIfAbsent(key(r.getType(), r.getNamespace(), r.getName()), r);
                }
            }
        }

        <T extends KubernetesResource> T find(ResourceType type, Class<T> cls,
                                              String namespace, String name) {
            if (name == null) {
                return null;
            }
            KubernetesResource found = byKey.get(key(type, namespace, name));
            return cls.isInstance(found) ? cls.cast(found) : null;
        }

        private static String key(ResourceType type, String namespace, String name) {
            return type + "|" + (namespace == null ? "" : namespace) + "|" + name;
        }
    }
}