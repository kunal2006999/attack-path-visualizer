package com.kunal.attackpathvisualizer.report;

import com.kunal.attackpathvisualizer.common.exception.LiveClusterScanException;
import com.kunal.attackpathvisualizer.core.pipeline.ClusterGraphPipeline;
import com.kunal.attackpathvisualizer.security.SecurityAnalysisService;
import com.kunal.attackpathvisualizer.security.SecurityReport;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientBuilder;
import org.springframework.stereotype.Service;

import java.util.Objects;

/**
 * Coordinates:
 *
 * Kubernetes cluster
 *      -> live resource scanning
 *      -> cluster snapshot
 *      -> graph construction
 *      -> security analysis
 *      -> JSON report
 *
 * The Kubernetes client is created and closed within this service.
 */
@Service
public class LiveSecurityReportService {

    public record ExportedReport(
            String clusterName,
            SecurityReport report,
            String json
    ) {
    }

    private final ClusterGraphPipeline pipeline;
    private final SecurityAnalysisService securityAnalysisService;
    private final SecurityReportExporter exporter;

    public LiveSecurityReportService(
            ClusterGraphPipeline pipeline,
            SecurityAnalysisService securityAnalysisService,
            SecurityReportExporter exporter) {

        this.pipeline = Objects.requireNonNull(
                pipeline, "Pipeline cannot be null");

        this.securityAnalysisService = Objects.requireNonNull(
                securityAnalysisService,
                "Security analysis service cannot be null");

        this.exporter = Objects.requireNonNull(
                exporter, "Exporter cannot be null");
    }

    /**
     * Scans the Kubernetes cluster accessible through the current
     * Kubernetes client configuration.
     *
     * @param clusterName display name to use in the generated report
     * @return the analyzed report and its JSON representation
     */
    public ExportedReport scan(String clusterName) {

        if (clusterName == null || clusterName.isBlank()) {
            throw new IllegalArgumentException(
                    "Cluster name must not be empty");
        }

        try (KubernetesClient client =
                     new KubernetesClientBuilder().build()) {

            ClusterGraphPipeline.PipelineResult pipelineResult =
                    pipeline.buildFromLiveCluster(client, clusterName);

            SecurityReport report =
                    securityAnalysisService.analyze(pipelineResult);

            String json =
                    exporter.export(clusterName, report);

            return new ExportedReport(
                    clusterName,
                    report,
                    json
            );

        } catch (Exception e) {
            throw new LiveClusterScanException(
                    "Live Kubernetes scan failed. Verify that the cluster "
                            + "is reachable and the configured Kubernetes "
                            + "identity has sufficient permissions.",
                    e
            );
        }
    }
}