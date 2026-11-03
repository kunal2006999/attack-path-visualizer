package com.kunal.attackpathvisualizer.report;

import com.kunal.attackpathvisualizer.common.model.snapshot.ClusterSnapshot;
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

    public SecurityReportController(SecurityReportExportService exportService) {
        this.exportService = exportService;
    }

    /**
     * Accepts a cluster snapshot (JSON), runs the security analysis and returns
     * the report as JSON. With {@code ?download=true} the response is sent as
     * an attachment.
     */
    @PostMapping(
            value = "/export",
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> export(
            @RequestBody(required = false) ClusterSnapshot snapshot,
            @RequestParam(name = "download", defaultValue = "false") boolean download) {

        SecurityReportExportService.ExportedReport exported =
                exportService.export(snapshot);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        if (download) {
            headers.setContentDisposition(
                    ContentDisposition.attachment()
                            .filename(fileName(exported.clusterName()))
                            .build());
        }

        return ResponseEntity.ok().headers(headers).body(exported.json());
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