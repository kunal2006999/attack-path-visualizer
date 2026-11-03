package com.kunal.attackpathvisualizer.security;

import com.kunal.attackpathvisualizer.graph.GraphNode;
import org.springframework.stereotype.Component;

import java.util.Objects;

@Component
public class RecommendationEngine {

    public String recommend(Finding finding) {
        Objects.requireNonNull(
                finding,
                "Finding cannot be null"
        );

        return recommendForGrantSource(
                findGrantSource(finding)
        );
    }

    public String recommendForGrantSource(GraphNode grantSource) {
        Objects.requireNonNull(
                grantSource,
                "Grant source cannot be null"
        );

        String resourceType =
                grantSource.getResourceType().name();

        return switch (resourceType) {
            case "CLUSTER_ROLE_BINDING" ->
                    "Review the ClusterRoleBinding's subjects and "
                            + "referenced ClusterRole. Remove unnecessary "
                            + "Secret permissions and restrict access to "
                            + "the required subjects.";

            case "ROLE_BINDING" ->
                    "Review the RoleBinding's subjects and referenced "
                            + "Role or ClusterRole. Remove unnecessary Secret "
                            + "permissions and confirm that the binding is "
                            + "restricted to the required namespace.";

            case "ROLE" ->
                    "Review the Role's rules, especially permissions "
                            + "to get, list, or watch Secrets. Remove "
                            + "unnecessary permissions and restrict access "
                            + "to the required resources.";

            case "CLUSTER_ROLE" ->
                    "Review the ClusterRole's rules and remove "
                            + "unnecessary Secret permissions. Confirm that "
                            + "its bindings grant access only to the required "
                            + "subjects and scope.";

            default ->
                    "Review the resource's permissions and its "
                            + "relationship to the target Secret. Verify "
                            + "that the modeled access is required and "
                            + "remove unnecessary permissions.";
        };
    }

    private GraphNode findGrantSource(Finding finding) {
        var path = finding.attackPath();

        if (path.size() < 2) {
            return finding.entryPoint();
        }

        /*
         * The final node is the target Secret.
         * The preceding node is the source of the final CAN_ACCESS
         * edge in the attack path.
         */
        return path.get(path.size() - 2);
    }
}