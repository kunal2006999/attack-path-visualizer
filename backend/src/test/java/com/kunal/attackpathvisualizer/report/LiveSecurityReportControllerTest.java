package com.kunal.attackpathvisualizer.report;

import com.kunal.attackpathvisualizer.common.exception.GlobalExceptionHandler;
import com.kunal.attackpathvisualizer.common.exception.LiveClusterScanException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class LiveSecurityReportControllerTest {

    private LiveSecurityReportService liveService;
    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        SecurityReportExportService exportService =
                mock(SecurityReportExportService.class);

        liveService = mock(LiveSecurityReportService.class);

        SecurityReportController controller =
                new SecurityReportController(exportService, liveService);

        mockMvc = MockMvcBuilders
                .standaloneSetup(controller)
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    @Test
    void scanReturnsJsonReport() throws Exception {

        when(liveService.scan("minikube"))
                .thenReturn(new LiveSecurityReportService.ExportedReport(
                        "minikube",
                        null,
                        "{\"clusterName\":\"minikube\",\"totalFindings\":0}"
                ));

        mockMvc.perform(post("/api/security/reports/scan")
                        .param("clusterName", "minikube"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(
                        MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.clusterName").value("minikube"))
                .andExpect(jsonPath("$.totalFindings").value(0));

        verify(liveService).scan("minikube");
    }

    @Test
    void scanReturnsDownloadableAttachment() throws Exception {

        when(liveService.scan("minikube"))
                .thenReturn(new LiveSecurityReportService.ExportedReport(
                        "minikube",
                        null,
                        "{\"clusterName\":\"minikube\"}"
                ));

        mockMvc.perform(post("/api/security/reports/scan")
                        .param("clusterName", "minikube")
                        .param("download", "true"))
                .andExpect(status().isOk())
                .andExpect(header().string(
                        "Content-Disposition",
                        org.hamcrest.Matchers.containsString("attachment")))
                .andExpect(header().string(
                        "Content-Disposition",
                        org.hamcrest.Matchers.containsString(
                                "security-report-minikube.json")));

        verify(liveService).scan("minikube");
    }

    @Test
    void scanFailureReturnsBadGateway() throws Exception {

        when(liveService.scan("minikube"))
                .thenThrow(new LiveClusterScanException(
                        "Live Kubernetes scan failed.",
                        new RuntimeException("Connection refused")
                ));

        mockMvc.perform(post("/api/security/reports/scan")
                        .param("clusterName", "minikube"))
                .andExpect(status().isBadGateway())
                .andExpect(jsonPath("$.status").value(502))
                .andExpect(jsonPath("$.message")
                        .value("Live Kubernetes scan failed."));

        verify(liveService).scan("minikube");
    }

    @Test
    void scanRejectsBlankClusterName() throws Exception {

        mockMvc.perform(post("/api/security/reports/scan")
                        .param("clusterName", " "))
                .andExpect(status().isBadRequest());

        verifyNoInteractions(liveService);
    }
}