package com.kunal.attackpathvisualizer.core.pipeline;

import com.kunal.attackpathvisualizer.common.util.ClusterSnapshotParser;
import com.kunal.attackpathvisualizer.core.builder.ClusterSnapshotMapper;
import com.kunal.attackpathvisualizer.core.validation.ClusterSnapshotValidator;
import com.kunal.attackpathvisualizer.graph.GraphBuilder;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientBuilder;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** Requires a reachable cluster (e.g. Minikube). Run with: ./mvnw test -Pintegration */
@Tag("integration")
class LiveClusterPipelineIT {

    @Test
    void liveClusterBuildsNonEmptyGraph() {
        ClusterGraphPipeline pipeline = new ClusterGraphPipeline(
                new ClusterSnapshotParser(), new ClusterSnapshotValidator(),
                new ClusterSnapshotMapper(), new GraphBuilder());

        try (KubernetesClient client = new KubernetesClientBuilder().build()) {
            var result = pipeline.buildFromLiveCluster(client, "minikube");

            assertTrue(result.graph().getNodeCount() > 0);
            assertNotNull(result.graph().getNode("NAMESPACE:kube-system"));
        }
    }
}