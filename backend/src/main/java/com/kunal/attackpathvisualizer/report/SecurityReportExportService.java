package com.kunal.attackpathvisualizer.report;

import com.kunal.attackpathvisualizer.common.exception.InvalidClusterSnapshotException;
import com.kunal.attackpathvisualizer.common.model.snapshot.ClusterSnapshot;
import com.kunal.attackpathvisualizer.core.pipeline.ClusterGraphPipeline;
import com.kunal.attackpathvisualizer.security.SecurityAnalysisService;
import com.kunal.attackpathvisualizer.security.SecurityReport;
import org.springframework.stereotype.Service;

import java.util.Objects;

/**
 * Coordinates snapshot -> graph pipeline -> security analysis -> JSON export.
 * Contains no analysis logic of its own.
 */
@Service
public class SecurityReportExportService {

    public record ExportedReport(
            String clusterName,
            SecurityReport report,
            String json
    ) {
    }

    private final ClusterGraphPipeline pipeline;
    private final SecurityAnalysisService securityAnalysisService;
    private final SecurityReportExporter exporter;

    public SecurityReportExportService(
            ClusterGraphPipeline pipeline,
            SecurityAnalysisService securityAnalysisService,
            SecurityReportExporter exporter) {
        this.pipeline = Objects.requireNonNull(pipeline, "Pipeline cannot be null");
        this.securityAnalysisService = Objects.requireNonNull(
                securityAnalysisService, "Security analysis service cannot be null");
        this.exporter = Objects.requireNonNull(exporter, "Exporter cannot be null");
    }

    /**
     * @throws InvalidClusterSnapshotException if the snapshot is null or fails validation
     */
    public ExportedReport export(ClusterSnapshot snapshot) {
        if (snapshot == null) {
            throw new InvalidClusterSnapshotException(
                    "Request body must contain a cluster snapshot");
        }

        ClusterGraphPipeline.PipelineResult pipelineResult;
        try {
            pipelineResult = pipeline.build(snapshot);
        } catch (IllegalArgumentException e) {
            // Only snapshot validation/mapping failures are client errors.
            throw new InvalidClusterSnapshotException(e.getMessage(), e);
        }

        SecurityReport report = securityAnalysisService.analyze(pipelineResult);
        String json = exporter.export(snapshot.getClusterName(), report);

        return new ExportedReport(snapshot.getClusterName(), report, json);
    }
}