package com.kunal.attackpathvisualizer.report;

import com.kunal.attackpathvisualizer.common.exception.LiveClusterScanException;
import com.kunal.attackpathvisualizer.common.exception.InvalidClusterSnapshotException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/security/reports")
public class SecurityReportController {

    private final SecurityReportExportService exportService;
    private final LiveSecurityReportService liveSecurityReportService;

    /**
     * Constructor used by Spring.
     */
    @Autowired
    public SecurityReportController(
            SecurityReportExportService exportService,
            LiveSecurityReportService liveSecurityReportService) {

        this.exportService = exportService;
        this.liveSecurityReportService = liveSecurityReportService;
    }

    /**
     * Backward-compatible constructor for existing tests that only
     * exercise the snapshot export endpoint.
     */
    public SecurityReportController(
            SecurityReportExportService exportService) {

        this.exportService = exportService;
        this.liveSecurityReportService = null;
    }

    /**
     * Accepts a cluster snapshot as JSON, performs security analysis,
     * and returns the generated report.
     *
     * Add ?download=true to return the report as an attachment.
     */
    @PostMapping(
            value = "/export",
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> export(
            @RequestBody(required = false) com.kunal.attackpathvisualizer.common.model.snapshot.ClusterSnapshot snapshot,
            @RequestParam(name = "download", defaultValue = "false")
            boolean download) {

        SecurityReportExportService.ExportedReport exported =
                exportService.export(snapshot);

        HttpHeaders headers = jsonHeaders();

        if (download) {
            headers.setContentDisposition(
                    ContentDisposition.attachment()
                            .filename(fileName(exported.clusterName()))
                            .build());
        }

        return ResponseEntity.ok()
                .headers(headers)
                .body(exported.json());
    }

    /**
     * Scans the currently configured Kubernetes cluster and generates
     * a security report.
     *
     * Example:
     * POST /api/security/reports/scan?clusterName=minikube
     *
     * Add ?download=true to download the JSON report.
     */
    @PostMapping(
            value = "/scan",
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> scan(
            @RequestParam(name = "clusterName") String clusterName,
            @RequestParam(name = "download", defaultValue = "false")
            boolean download) {

        if (liveSecurityReportService == null) {
            throw new IllegalStateException(
                    "Live security report service is not configured");
        }

        if (clusterName == null || clusterName.isBlank()) {
            throw new InvalidClusterSnapshotException(
                    "Cluster name must not be empty");
        }

        LiveSecurityReportService.ExportedReport exported =
                liveSecurityReportService.scan(clusterName);

        HttpHeaders headers = jsonHeaders();

        if (download) {
            headers.setContentDisposition(
                    ContentDisposition.attachment()
                            .filename(fileName(exported.clusterName()))
                            .build());
        }

        return ResponseEntity.ok()
                .headers(headers)
                .body(exported.json());
    }

    private static HttpHeaders jsonHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        return headers;
    }

    private static String fileName(String clusterName) {
        String safe = clusterName == null
                ? ""
                : clusterName.replaceAll("[^A-Za-z0-9._-]", "_");

        if (safe.isBlank()) {
            safe = "cluster";
        }

        return "security-report-" + safe + ".json";
    }
}