package com.kunal.attackpathvisualizer.core.pipeline;

import com.kunal.attackpathvisualizer.common.model.snapshot.ClusterSnapshot;
import com.kunal.attackpathvisualizer.common.util.ClusterSnapshotParser;
import com.kunal.attackpathvisualizer.core.builder.ClusterSnapshotMapper;
import com.kunal.attackpathvisualizer.core.model.Cluster;
import com.kunal.attackpathvisualizer.core.validation.ClusterSnapshotValidator;
import com.kunal.attackpathvisualizer.graph.AttackGraph;
import com.kunal.attackpathvisualizer.graph.GraphBuilder;
import com.kunal.attackpathvisualizer.scanner.ClusterSnapshotAssembler;
import com.kunal.attackpathvisualizer.scanner.ScannerException;
import io.fabric8.kubernetes.client.KubernetesClient;

import java.io.IOException;
import java.nio.file.Path;

/**
 * Single entry point: snapshot (live or JSON) → validate → Cluster → AttackGraph.
 * Read-only with respect to Kubernetes. The caller supplies (and closes) the client.
 *
 * <h3>Error handling</h3>
 * <ul>
 *   <li>{@link #buildFromJson(Path)} propagates {@link IOException} for file-access failures
 *       and {@link IllegalArgumentException} for invalid snapshot content.</li>
 *   <li>{@link #buildFromLiveCluster(KubernetesClient, String)} propagates
 *       {@link ScannerException} when any resource category cannot be retrieved from the
 *       Kubernetes API. The exception is never silently converted to an empty graph —
 *       callers must handle or propagate it explicitly.</li>
 *   <li>{@link #build(ClusterSnapshot)} propagates {@link IllegalArgumentException}
 *       from snapshot validation.</li>
 * </ul>
 */
@org.springframework.stereotype.Component
public class ClusterGraphPipeline {

    public record PipelineResult(ClusterSnapshot snapshot, Cluster cluster, AttackGraph graph) {}

    private final ClusterSnapshotParser parser;
    private final ClusterSnapshotValidator validator;
    private final ClusterSnapshotMapper mapper;
    private final GraphBuilder graphBuilder;

    public ClusterGraphPipeline(ClusterSnapshotParser parser,
                                ClusterSnapshotValidator validator,
                                ClusterSnapshotMapper mapper,
                                GraphBuilder graphBuilder) {
        this.parser = parser;
        this.validator = validator;
        this.mapper = mapper;
        this.graphBuilder = graphBuilder;
    }

    /**
     * Validates {@code snapshot}, maps it to a {@link Cluster}, and builds an
     * {@link AttackGraph}.
     *
     * @throws IllegalArgumentException if the snapshot fails validation
     */
    public PipelineResult build(ClusterSnapshot snapshot) {
        validator.validate(snapshot);
        Cluster cluster = mapper.map(snapshot);
        AttackGraph graph = graphBuilder.build(cluster);
        return new PipelineResult(snapshot, cluster, graph);
    }

    /**
     * Parses a JSON snapshot file and runs it through the pipeline.
     *
     * @throws IOException if the file cannot be read or parsed
     * @throws IllegalArgumentException if the parsed snapshot fails validation
     */
    public PipelineResult buildFromJson(Path file) throws IOException {
        return build(parser.parse(file));
    }

    /**
     * Scans a live cluster and runs the result through the pipeline.
     *
     * <p>If any resource scanner fails (connection refused, timeout, RBAC denial,
     * malformed API response), a {@link ScannerException} is thrown immediately.
     * The pipeline does <em>not</em> return a partial or empty graph on scanner failure —
     * an incomplete graph would be misleading for attack-path analysis.
     *
     * @param client      a connected, non-null Kubernetes client; the caller is responsible
     *                    for closing it after this method returns
     * @param clusterName a non-blank cluster identifier to embed in the snapshot
     * @throws ScannerException         if any resource category cannot be retrieved
     * @throws IllegalArgumentException if {@code client} or {@code clusterName} is invalid,
     *                                  or if the assembled snapshot fails validation
     */
    public PipelineResult buildFromLiveCluster(KubernetesClient client, String clusterName) {
        ClusterSnapshot snapshot = new ClusterSnapshotAssembler(client, clusterName).scanCluster();
        return build(snapshot);
    }
}