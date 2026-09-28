#include "view_dashboard.hpp"
#include "ui_theme.hpp"
#include "app_context.hpp"
#include <forensivault/drive_sanitizer.hpp>
#include <logging/audit_logger.hpp>

#include <imgui.h>
#include <string>

namespace forensivault::gui {

void ViewDashboard::render() {
    UITheme::renderCardHeader("FORENSIC WORKSTATION DASHBOARD",
                              "Dual-Domain Operational Engine: Evidence Recovery (Read-Only) vs Certified Sanitization (Destructive)");

    renderMetricsOverview();
    renderQuickLaunchModules();
    renderForensicReadiness();
    renderRecentOperations();
}

void ViewDashboard::renderMetricsOverview() {
    auto& ctx = AppContext::getInstance();

    float totalW = ImGui::GetContentRegionAvail().x;
    float cardW = (totalW - 36.0f) / 4.0f;
    if (cardW < 180.0f) cardW = 180.0f;

    // Card 1: Platform & Privileges
    const char* privLabel = ctx.isElevated ? "Admin / Elevated" : "Standard User";
    ImVec4 privCol = ctx.isElevated ? UITheme::COLOR_GREEN : UITheme::COLOR_YELLOW;
    UITheme::renderMetricTile("Security Context", privLabel, ctx.platformName.c_str(), privCol, cardW);

    ImGui::SameLine();
    // Card 2: Recovered Artifacts (Preservation domain)
    std::string recCount = std::to_string(ctx.recoveredFilesRegistry.size());
    UITheme::renderMetricTile("Evidence Recovered", recCount.c_str(), "Read-Only Carved & Parsed", UITheme::COLOR_BLUE, cardW);

    ImGui::SameLine();
    // Card 3: Sanitized Data (Destruction domain)
    std::string eraseCount = std::to_string(ctx.totalFilesErased);
    UITheme::renderMetricTile("Sanitized Artifacts", eraseCount.c_str(), "Certified NIST/DoD Eradicated", UITheme::COLOR_ORANGE, cardW);

    ImGui::SameLine();
    // Card 4: Audit Chain
    bool chainOk = forensivault::logging::AuditLogger::getInstance().verifyChain();
    const char* chainText = chainOk ? "100% Intact" : "Tamper Detected";
    ImVec4 chainCol = chainOk ? UITheme::COLOR_GREEN : UITheme::COLOR_RED;
    UITheme::renderMetricTile("Audit Journal", chainText, "Chained SHA-256 Ledger", chainCol, cardW);

    ImGui::Spacing();
}

void ViewDashboard::renderQuickLaunchModules() {
    auto& ctx = AppContext::getInstance();

    float availW = ImGui::GetContentRegionAvail().x;
    float colW = (availW - 16.0f) * 0.5f;
    if (colW < 320.0f) colW = availW;

    // =========================================================================
    // DUAL-DOMAIN SECTION: CLEAR SEPARATION OF RECOVERY VS DESTRUCTION
    // =========================================================================

    ImGui::Columns(2, "DualDomainColumns", false);
    ImGui::SetColumnWidth(0, colW + 8.0f);

    // -------------------------------------------------------------------------
    // DOMAIN 1: FORENSIC DATA RECOVERY (EVIDENCE PRESERVATION)
    // -------------------------------------------------------------------------
    if (UITheme::beginCard("DomainRecoveryCard", "DOMAIN 1: FORENSIC RECOVERY & PRESERVATION",
                           "STRICT READ-ONLY", UITheme::COLOR_BLUE)) {
        ImGui::TextColored(UITheme::COLOR_BLUE, "[Preservation Operations]");
        ImGui::TextColored(UITheme::COLOR_TEXT_SECONDARY,
            "Non-destructive discovery, cluster parsing, and evidence reconstruction without modifying source storage media.");
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // Recovery Tool 1: Filesystem Metadata Recovery
        if (UITheme::beginCard("RecSubCard_Fs", "Filesystem Metadata Recovery", "FAT32 / exFAT / NTFS", UITheme::COLOR_BLUE, 115.0f)) {
            ImGui::TextColored(UITheme::COLOR_TEXT_PRIMARY, "Reconstructs directory trees, file names, and timestamps from volume tables and $MFT.");
            ImGui::Spacing();
            if (UITheme::renderRecoveryButton("Launch Filesystem Recovery ->", ImVec2(-1, 32))) {
                ctx.activeTab = ModuleTab::FS_RECOVERY;
            }
        }
        UITheme::endCard();

        // Recovery Tool 2: Deep Raw Data File Carving
        if (UITheme::beginCard("RecSubCard_Carver", "Advanced Raw Data File Carver", "SIGNATURE CARVING", UITheme::COLOR_BLUE, 115.0f)) {
            ImGui::TextColored(UITheme::COLOR_TEXT_PRIMARY, "Bypasses corrupted filesystems. Carves PDF, DOCX, XLSX, OLE, JPEG, and MP4 from unallocated clusters.");
            ImGui::Spacing();
            if (UITheme::renderRecoveryButton("Launch Raw File Carver ->", ImVec2(-1, 32))) {
                ctx.activeTab = ModuleTab::FILE_CARVER;
            }
        }
        UITheme::endCard();

        // Recovery Tool 3: Recovered Evidence Catalog
        if (UITheme::beginCard("RecSubCard_Catalog", "Recovered Evidence Browser", "ARTIFACT REGISTRY", UITheme::COLOR_BLUE, 115.0f)) {
            ImGui::TextColored(UITheme::COLOR_TEXT_PRIMARY, "Filter, inspect, and export all recovered files with confidence scores and SHA-256 hashes.");
            ImGui::Spacing();
            if (UITheme::renderSecondaryButton("Open Recovered Files Browser ->", ImVec2(-1, 32))) {
                ctx.activeTab = ModuleTab::RECOVERED_FILES;
            }
        }
        UITheme::endCard();
    }
    UITheme::endCard();

    ImGui::NextColumn();

    // -------------------------------------------------------------------------
    // DOMAIN 2: SECURE DATA SANITIZATION (DATA ERADICATION)
    // -------------------------------------------------------------------------
    if (UITheme::beginCard("DomainSanitizeCard", "DOMAIN 2: SECURE SANITIZATION & ERADICATION",
                           "PERMANENT DESTRUCTION", UITheme::COLOR_ORANGE)) {
        ImGui::TextColored(UITheme::COLOR_ORANGE, "[Destructive Overwrite Operations]");
        ImGui::TextColored(UITheme::COLOR_TEXT_SECONDARY,
            "Permanent data eradication compliant with NIST SP 800-88 Rev 1 and DoD 5220.22-M to prevent unauthorized recovery.");
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // Sanitization Tool 1: Certified Drive Sanitizer
        if (UITheme::beginCard("SanSubCard_Drive", "Certified Drive & Media Sanitizer", "NIST SP 800-88 R1", UITheme::COLOR_ORANGE, 115.0f)) {
            ImGui::TextColored(UITheme::COLOR_TEXT_PRIMARY, "Block-level physical and virtual image overwrites (Single-pass 0x00, DoD 3-Pass, CSPRNG) with sector verification.");
            ImGui::Spacing();
            if (UITheme::renderPrimaryButton("Launch Drive Sanitizer ->", ImVec2(-1, 32))) {
                ctx.activeTab = ModuleTab::DRIVE_SANITIZER;
            }
        }
        UITheme::endCard();

        // Sanitization Tool 2: Secure File & Folder Eraser
        if (UITheme::beginCard("SanSubCard_File", "Secure File & Folder Eraser", "3x METADATA SCRAMBLE", UITheme::COLOR_ORANGE, 115.0f)) {
            ImGui::TextColored(UITheme::COLOR_TEXT_PRIMARY, "Targeted cluster overwrite with unbuffered cache flush and 3-pass randomized directory entry renaming.");
            ImGui::Spacing();
            if (UITheme::renderPrimaryButton("Launch File Eraser ->", ImVec2(-1, 32))) {
                ctx.activeTab = ModuleTab::FILE_ERASER;
            }
        }
        UITheme::endCard();

        // Sanitization Tool 3: Storage Devices & Hardware Interlocks
        if (UITheme::beginCard("SanSubCard_Devices", "Storage Devices & Hardware Interlocks", "ROOT DRIVE LOCK", UITheme::COLOR_ORANGE, 115.0f)) {
            ImGui::TextColored(UITheme::COLOR_TEXT_PRIMARY, "Enumerate physical storage devices, inspect bus interfaces, and verify OS root drive protection locks.");
            ImGui::Spacing();
            if (UITheme::renderSecondaryButton("Inspect Devices & Locks ->", ImVec2(-1, 32))) {
                ctx.activeTab = ModuleTab::DEVICE_DETECTOR;
            }
        }
        UITheme::endCard();
    }
    UITheme::endCard();

    ImGui::Columns(1);
    ImGui::Spacing();
}

void ViewDashboard::renderForensicReadiness() {
    if (UITheme::beginCard("DashCard_Readiness", "Forensic Safety Interlocks & Immutability Guarantees",
                           "STANDARDS COMPLIANT", UITheme::COLOR_GREEN)) {
        ImGui::Columns(3, nullptr, false);

        ImGui::TextColored(UITheme::COLOR_GREEN, "[ ACTIVE ] Root Drive Interlock");
        ImGui::TextColored(UITheme::COLOR_TEXT_MUTED, "OS boot drives and primary system partitions are permanently locked against sanitization.");

        ImGui::NextColumn();
        ImGui::TextColored(UITheme::COLOR_BLUE, "[ ACTIVE ] Evidence Read-Only Mode");
        ImGui::TextColored(UITheme::COLOR_TEXT_MUTED, "Disk image and raw evidence streams are opened in strictly immutable, read-only mode.");

        ImGui::NextColumn();
        ImGui::TextColored(UITheme::COLOR_GREEN, "[ ACTIVE ] Cryptographic Audit Trail");
        ImGui::TextColored(UITheme::COLOR_TEXT_MUTED, "Every forensic scan and erasure is recorded with chained SHA-256 hash validation.");

        ImGui::Columns(1);
    }
    UITheme::endCard();
}

void ViewDashboard::renderRecentOperations() {
    auto entries = forensivault::logging::AuditLogger::getInstance().getEntries();

    if (UITheme::beginCard("DashCard_RecentAudit", "Recent Operational Audit Log",
                           "TAMPER-EVIDENT JOURNAL", UITheme::COLOR_ORANGE)) {
        if (entries.empty()) {
            ImGui::TextColored(UITheme::COLOR_TEXT_MUTED, "No forensic operations logged in the current session.");
        } else {
            if (ImGui::BeginTable("DashAuditTable", 4, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_ScrollY, ImVec2(0, 140))) {
                ImGui::TableSetupColumn("Timestamp (UTC)", ImGuiTableColumnFlags_WidthFixed, 180.0f);
                ImGui::TableSetupColumn("Module / Operation", ImGuiTableColumnFlags_WidthFixed, 180.0f);
                ImGui::TableSetupColumn("Target Source", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                ImGui::TableHeadersRow();

                size_t startIdx = (entries.size() > 5) ? entries.size() - 5 : 0;
                for (size_t i = entries.size(); i > startIdx; --i) {
                    const auto& e = entries[i - 1];
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    ImGui::Text("%s", e.timestamp_iso.c_str());

                    ImGui::TableSetColumnIndex(1);
                    if (e.operation_type.find("RECOVERY") != std::string::npos || e.operation_type.find("CARVE") != std::string::npos) {
                        ImGui::TextColored(UITheme::COLOR_BLUE, "%s", e.operation_type.c_str());
                    } else {
                        ImGui::TextColored(UITheme::COLOR_ORANGE, "%s", e.operation_type.c_str());
                    }

                    ImGui::TableSetColumnIndex(2);
                    ImGui::Text("%s", e.source_identifier.c_str());

                    ImGui::TableSetColumnIndex(3);
                    if (e.status == "SUCCESS") {
                        UITheme::renderBadge("SUCCESS", UITheme::COLOR_GREEN);
                    } else {
                        UITheme::renderBadge(e.status.c_str(), UITheme::COLOR_RED);
                    }
                }
                ImGui::EndTable();
            }
        }
    }
    UITheme::endCard();
}

} // namespace forensivault::gui
