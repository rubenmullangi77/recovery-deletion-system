#include "view_audit_log.hpp"
#include "ui_theme.hpp"
#include "file_dialog.hpp"
#include "app_context.hpp"

#include <imgui.h>
#include <iomanip>
#include <sstream>

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
        if (UITheme::renderSecondaryButton("Refresh Entries", ImVec2(160, 34))) {
            refreshLog();
        }

        ImGui::SameLine();

        size_t brokenIdx = 0;
        bool chainIntact = forensivault::logging::AuditLogger::getInstance().verifyChain(&brokenIdx);

        if (UITheme::renderSecondaryButton("Verify Chain Integrity", ImVec2(200, 34))) {
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

        ImGui::SameLine();
        if (chainIntact) {
            UITheme::renderBadge("CHAIN INTACT [100% VERIFIED]", UITheme::COLOR_GREEN);
        } else {
            UITheme::renderBadge("TAMPER DETECTED [INVALID HASH]", UITheme::COLOR_RED);
        }

        ImGui::SameLine(ImGui::GetWindowWidth() - 260.0f);

        if (UITheme::renderPrimaryButton("Export Journal (.jsonl)...", ImVec2(240, 34))) {
            std::string savePath = FileDialog::saveFile("Export Forensic Audit Journal", "audit_log.jsonl", "JSON Lines (*.jsonl)", "*.jsonl;*.json;*.*");
            if (!savePath.empty()) {
                if (forensivault::logging::AuditLogger::getInstance().saveToFile(savePath)) {
                    AppContext::getInstance().postNotification(
                        Notification::Type::SUCCESS, "Audit Exported",
                        "Saved chained audit journal to: " + savePath);
                } else {
                    AppContext::getInstance().postNotification(
                        Notification::Type::FAILURE, "Export Failed",
                        "Could not write audit journal to: " + savePath);
                }
            }
        }
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
                    ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY;

        if (ImGui::BeginTable("AuditTable", 5, flags, ImVec2(0, 380))) {
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
