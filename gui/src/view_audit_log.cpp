#include "view_audit_log.hpp"
#include "ui_theme.hpp"
#include "file_dialog.hpp"
#include "app_context.hpp"
#include "reporting/report_generator.hpp"
#include "reporting/forensic_report.hpp"
#include <forensivault/core/platform.hpp>

#include <imgui.h>
#include <iomanip>
#include <sstream>
#include <filesystem>

namespace forensivault::gui {

ViewAuditLog::ViewAuditLog() {
    refreshLog();
}

void ViewAuditLog::refreshLog() {
    entries_ = forensivault::logging::AuditLogger::getInstance().getEntries();
}

void ViewAuditLog::render() {
    UITheme::renderCardHeader("FORENSIC OPERATION HISTORY & AUDIT JOURNAL",
                              "Cryptographically Chained SHA-256 Tamper-Evident Forensic Records (ISO/IEC 27040 Compliant)");

    // Action Toolbar Card
    if (UITheme::beginCard("AuditToolbarCard", "Journal Management & Cryptographic Chain Verification", "CHAIN OF CUSTODY", UITheme::COLOR_ORANGE)) {
        float availW = ImGui::GetContentRegionAvail().x;
        float spacing = ImGui::GetStyle().ItemSpacing.x;

        if (UITheme::renderSecondaryButton("Refresh Entries", ImVec2(150, 34))) {
            refreshLog();
        }
        ImGui::SameLine(0.0f, spacing);

        size_t brokenIdx = 0;
        bool chainIntact = forensivault::logging::AuditLogger::getInstance().verifyChain(&brokenIdx);

        if (UITheme::renderSecondaryButton("Verify Chain Integrity", ImVec2(190, 34))) {
            if (chainIntact) {
                AppContext::getInstance().postNotification(
                    Notification::Type::SUCCESS, "Audit Chain Verified",
                    "Cryptographic SHA-256 chain is 100% intact across all records.");
            } else {
                AppContext::getInstance().postNotification(
                    Notification::Type::FAILURE, "Tamper Detected",
                    "Hash mismatch detected at journal index " + std::to_string(brokenIdx));
            }
        }
        ImGui::SameLine(0.0f, spacing);

        if (chainIntact) {
            UITheme::renderBadge("CHAIN INTACT [100% VERIFIED]", UITheme::COLOR_GREEN);
        } else {
            UITheme::renderBadge("TAMPER DETECTED [INVALID HASH]", UITheme::COLOR_RED);
        }

        float exportBtnsW = 160.0f + 180.0f + spacing;
        float targetX = ImGui::GetWindowWidth() - exportBtnsW - 24.0f;
        if (availW > 880.0f && targetX > ImGui::GetCursorPosX() + 16.0f) {
            ImGui::SameLine(targetX);
        } else {
            ImGui::Dummy(ImVec2(0, 6.0f));
        }

        if (UITheme::renderSecondaryButton("Export Log (.txt)...", ImVec2(160, 34))) {
            std::string savePath = FileDialog::saveFile("Export Forensic Audit Log", "audit_log.txt", "Text Files (*.txt)", "*.txt;*.*");
            if (!savePath.empty()) {
                if (forensivault::logging::AuditLogger::getInstance().saveToTextFile(savePath)) {
                    AppContext::getInstance().postNotification(
                        Notification::Type::SUCCESS, "Audit Exported",
                        "Saved plain-text audit ledger to: " + savePath);
                } else {
                    AppContext::getInstance().postNotification(
                        Notification::Type::FAILURE, "Export Failed",
                        "Could not write audit ledger to: " + savePath);
                }
            }
        }

        ImGui::SameLine(0.0f, spacing);

        if (UITheme::renderPrimaryButton("Generate PDF Report", ImVec2(180, 34))) {
            forensivault::reporting::ForensicReport rep;
            rep.report_id = "AUDIT-" + std::to_string(std::time(nullptr));
            rep.report_timestamp_iso = forensivault::logging::AuditLogger::currentTimestampIso();
            rep.case_info.case_id = "CASE-AUDIT-LOG";
            rep.case_info.case_name = "Forensic Workstation Audit Trail";
            rep.case_info.investigator_name = AppContext::getInstance().currentUsername.empty() ? "Forensic Examiner" : AppContext::getInstance().currentUsername;
            rep.case_info.agency = "Digital Forensics Unit";
            rep.case_info.description = "Certified tamper-evident cryptographic audit report.";
            rep.audit_trail = entries_;
            rep.audit_entries_count = entries_.size();
            rep.audit_chain_verified = forensivault::logging::AuditLogger::getInstance().verifyChain();

            std::string reportsDir = forensivault::core::Platform::getReportsDirectory();
            auto res = forensivault::reporting::ReportGenerator::saveReportPackage(rep, reportsDir, true);
            if (res.pdf_saved) {
                AppContext::getInstance().postNotification(
                    Notification::Type::SUCCESS, "PDF Report Generated",
                    "Saved court-admissible PDF to: " + res.pdf_path);
            } else {
                AppContext::getInstance().postNotification(
                    Notification::Type::FAILURE, "PDF Generation Failed",
                    "Could not generate PDF report.");
            }
        }

        ImGui::Spacing();
        std::string defPath = forensivault::logging::AuditLogger::getDefaultLogPath();
        ImGui::TextColored(UITheme::COLOR_TEXT_SECONDARY, "Persistent Text Ledger: ");
        ImGui::SameLine();
        ImGui::TextColored(UITheme::COLOR_BLUE, "%s", defPath.c_str());
    }
    UITheme::endCard();

    if (entries_.empty()) {
        if (UITheme::beginCard("EmptyAuditCard", nullptr, nullptr, UITheme::COLOR_ORANGE, 100.0f)) {
            ImGui::TextColored(UITheme::COLOR_TEXT_MUTED, "No forensic operations logged in the current session.");
        }
        UITheme::endCard();
        return;
    }

    if (UITheme::beginCard("AuditEntriesCard", "Recorded Forensic Transactions", "AUDIT LEDGER", UITheme::COLOR_ORANGE)) {
        ImGui::TextColored(UITheme::COLOR_TEXT_SECONDARY, "Total Logged Entries: %zu", entries_.size());
        ImGui::Spacing();

        int flags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                    ImGuiTableFlags_Resizable;
        if (entries_.size() > 25) flags |= ImGuiTableFlags_ScrollY;
        float tableH = (entries_.size() > 25) ? 500.0f : 0.0f;

        if (ImGui::BeginTable("AuditTable", 5, flags, ImVec2(0, tableH))) {
            ImGui::TableSetupColumn("Timestamp (UTC)", ImGuiTableColumnFlags_WidthFixed, 180.0f);
            ImGui::TableSetupColumn("Operation", ImGuiTableColumnFlags_WidthFixed, 150.0f);
            ImGui::TableSetupColumn("Target Source", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Result", ImGuiTableColumnFlags_WidthFixed, 110.0f);
            ImGui::TableSetupColumn("Chained Entry SHA-256 Hash", ImGuiTableColumnFlags_WidthFixed, 220.0f);
            ImGui::TableHeadersRow();

            for (const auto& entry : entries_) {
                ImGui::TableNextRow();

                ImGui::TableSetColumnIndex(0);
                ImGui::Text("%s", entry.timestamp_iso.c_str());

                ImGui::TableSetColumnIndex(1);
                ImGui::TextColored(UITheme::COLOR_ORANGE, "%s", entry.operation_type.c_str());

                ImGui::TableSetColumnIndex(2);
                ImGui::Text("%s", entry.source_identifier.c_str());

                ImGui::TableSetColumnIndex(3);
                if (entry.status == "SUCCESS") {
                    UITheme::renderBadge("SUCCESS", UITheme::COLOR_GREEN);
                } else {
                    UITheme::renderBadge(entry.status.c_str(), UITheme::COLOR_RED);
                }

                ImGui::TableSetColumnIndex(4);
                if (UITheme::fontMono) ImGui::PushFont(UITheme::fontMono);
                if (!entry.entry_hash.empty()) {
                    std::string shortHash = (entry.entry_hash.size() > 20) ? entry.entry_hash.substr(0, 20) + "..." : entry.entry_hash;
                    ImGui::Text("%s", shortHash.c_str());
                } else {
                    ImGui::TextDisabled("—");
                }
                if (UITheme::fontMono) ImGui::PopFont();
            }

            ImGui::EndTable();
        }
    }
    UITheme::endCard();
}

} // namespace forensivault::gui
