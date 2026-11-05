package com.kunal.attackpathvisualizer.core.pipeline;

import com.kunal.attackpathvisualizer.analysis.AttackPathFinder;
import com.kunal.attackpathvisualizer.analysis.AttackPathResult;
import com.kunal.attackpathvisualizer.analysis.BlastRadiusAnalyzer;
import com.kunal.attackpathvisualizer.analysis.ReachabilityAnalyzer;
import com.kunal.attackpathvisualizer.common.model.snapshot.ClusterSnapshot;
import com.kunal.attackpathvisualizer.common.util.ClusterSnapshotParser;
import com.kunal.attackpathvisualizer.core.builder.ClusterSnapshotMapper;
import com.kunal.attackpathvisualizer.core.validation.ClusterSnapshotValidator;
import com.kunal.attackpathvisualizer.graph.GraphBuilder;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ClusterGraphPipelineTest {

    private final ClusterGraphPipeline pipeline = new ClusterGraphPipeline(
            new ClusterSnapshotParser(),
            new ClusterSnapshotValidator(),
            new ClusterSnapshotMapper(),
            new GraphBuilder());

    private ClusterGraphPipeline.PipelineResult load(String file) throws IOException {
        return pipeline.buildFromJson(Path.of("..", "sample-data", "clusters", file));
    }

    @Test
    void vulnerableClusterYieldsPotentialPathFromPodToSecret() throws IOException {
        var result = load("vulnerable-cluster.json");

        assertTrue(new ReachabilityAnalyzer(result.graph())
                .isReachable("POD:production:backend-pod", "SECRET:production:database-secret"));

        AttackPathResult path = new AttackPathFinder(result.graph())
                .findShortestPath("POD:production:backend-pod", "SECRET:production:database-secret");

        // Shortest potential path goes via the cluster-admin ClusterRoleBinding:
        // Pod -> ServiceAccount -> ClusterRoleBinding -> Secret (not proof of exploitability)
        assertEquals(4, path.getNodes().size());
        assertEquals(3, path.getTotalCost());
        assertEquals("POD:production:backend-pod", path.getNodes().get(0).getId());
        assertEquals("CLUSTER_ROLE_BINDING:backend-cluster-admin", path.getNodes().get(2).getId());
        assertEquals("SECRET:production:database-secret", path.getNodes().get(3).getId());
    }

    @Test
    void blastRadiusOfPodIncludesSecret() throws IOException {
        var result = load("vulnerable-cluster.json");
        var radius = new BlastRadiusAnalyzer(result.graph()).BlastRadius("POD:production:backend-pod");
        assertTrue(radius.getAffectedNodes().stream()
                .anyMatch(n -> n.getId().equals("SECRET:production:database-secret")));
    }

    @Test
    void isolatedClusterHasNoPathToSecret() throws IOException {
        var result = load("isolated-resources.json");
        assertFalse(new ReachabilityAnalyzer(result.graph())
                .isReachable("POD:production:isolated-pod", "SECRET:production:database-secret"));
    }

    @Test
    void multiPathClusterRespectsResourceNames() throws IOException {
        var result = load("multi-path-cluster.json");
        var reach = new ReachabilityAnalyzer(result.graph());
        assertTrue(reach.isReachable("POD:production:backend-pod", "SECRET:production:secret-a"));
        assertTrue(reach.isReachable("POD:production:backend-pod", "SECRET:production:secret-b"));
        // secret-a-reader must not point at secret-b
        assertTrue(result.graph().getOutgoingEdges("ROLE:production:secret-a-reader").stream()
                .noneMatch(e -> e.getTarget().getName().equals("secret-b")));
    }

    @Test
    void simpleClusterStillWorks() throws IOException {
        var result = load("simple-cluster.json");
        assertEquals(result.cluster().getResources().size(), result.graph().getNodeCount());
    }

    @Test
    void emptySnapshotProducesEmptyGraph() {
        ClusterSnapshot s = new ClusterSnapshot();
        s.setClusterName("empty");
        s.setPods(List.of());
        assertEquals(0, pipeline.build(s).graph().getNodeCount());
    }

    @Test
    void invalidSnapshotIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> pipeline.build(new ClusterSnapshot()));
    }
}