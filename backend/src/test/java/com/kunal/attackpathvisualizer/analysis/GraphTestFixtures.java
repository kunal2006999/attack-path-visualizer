package com.kunal.attackpathvisualizer.analysis;

import com.kunal.attackpathvisualizer.core.enums.ResourceType;
import com.kunal.attackpathvisualizer.core.relation.RelationshipType;
import com.kunal.attackpathvisualizer.graph.AttackGraph;
import com.kunal.attackpathvisualizer.graph.GraphEdge;
import com.kunal.attackpathvisualizer.graph.GraphNode;

public class GraphTestFixtures {

    public static AttackGraph createTestGraph() {
        AttackGraph graph = new AttackGraph();
        
        GraphNode pod = new GraphNode("Pod:default:my-pod", "uid1", ResourceType.POD, "my-pod", "default");
        GraphNode sa = new GraphNode("ServiceAccount:default:my-sa", "uid2", ResourceType.SERVICE_ACCOUNT, "my-sa", "default");
        GraphNode rb = new GraphNode("RoleBinding:default:my-rb", "uid3", ResourceType.ROLE_BINDING, "my-rb", "default");
        GraphNode role = new GraphNode("Role:default:my-role", "uid4", ResourceType.ROLE, "my-role", "default");
        GraphNode secret = new GraphNode("Secret:default:my-secret", "uid5", ResourceType.SECRET, "my-secret", "default");
        
        // Disconnected component
        GraphNode pod2 = new GraphNode("Pod:default:iso-pod", "uid6", ResourceType.POD, "iso-pod", "default");
        GraphNode sa2 = new GraphNode("ServiceAccount:default:iso-sa", "uid7", ResourceType.SERVICE_ACCOUNT, "iso-sa", "default");

        // Cycle nodes
        GraphNode c1 = new GraphNode("Pod:default:c1", "uid8", ResourceType.POD, "c1", "default");
        GraphNode c2 = new GraphNode("Pod:default:c2", "uid9", ResourceType.POD, "c2", "default");
        GraphNode c3 = new GraphNode("Pod:default:c3", "uid10", ResourceType.POD, "c3", "default");
        
        graph.addNode(pod);
        graph.addNode(sa);
        graph.addNode(rb);
        graph.addNode(role);
        graph.addNode(secret);
        graph.addNode(pod2);
        graph.addNode(sa2);
        graph.addNode(c1);
        graph.addNode(c2);
        graph.addNode(c3);

        // Branching paths to secret
        graph.addEdge(new GraphEdge(pod, sa, RelationshipType.USES, 1));
        graph.addEdge(new GraphEdge(sa, rb, RelationshipType.BINDS, 1));
        graph.addEdge(new GraphEdge(rb, role, RelationshipType.GRANTS, 1));
        graph.addEdge(new GraphEdge(role, secret, RelationshipType.CAN_ACCESS, 1));
        
        // Alternate cheaper path from sa to secret directly
        graph.addEdge(new GraphEdge(sa, secret, RelationshipType.CAN_ACCESS, 5));
        
        // Disconnected
        graph.addEdge(new GraphEdge(pod2, sa2, RelationshipType.USES, 1));

        // Cycle (c1 -> c2 -> c3 -> c1)
        graph.addEdge(new GraphEdge(c1, c2, RelationshipType.USES, 1));
        graph.addEdge(new GraphEdge(c2, c3, RelationshipType.USES, 1));
        graph.addEdge(new GraphEdge(c3, c1, RelationshipType.USES, 1));
        
        // Point from cycle to a visited node (not a cycle itself, but test false positives)
        graph.addEdge(new GraphEdge(c3, sa2, RelationshipType.USES, 1));

        return graph;
    }
}
