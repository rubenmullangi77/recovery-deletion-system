#include "view_operation_progress.hpp"
#include "ui_theme.hpp"
#include "app_context.hpp"

#include <imgui.h>
#include <iomanip>
#include <sstream>

namespace forensivault::gui {

void ViewOperationProgress::render() {
    UITheme::renderCardHeader("FORENSIC SCAN & OPERATION MONITOR",
                              "Real-time I/O Telemetry, Processing Throughput & Background Worker Execution");

    auto& ctx = AppContext::getInstance();
    auto& op = ctx.currentOperation;

    if (op.isRunning || op.hasFinished) {
        renderActiveOperation();
    } else {
        renderIdleState();
    }
}

void ViewOperationProgress::renderActiveOperation() {
    auto& ctx = AppContext::getInstance();
    auto& op = ctx.currentOperation;

    std::lock_guard<std::mutex> lock(op.mtx);

    const char* statusBadge = op.isRunning ? "RUNNING" : (op.success ? "COMPLETED" : "FAILED");
    ImVec4 badgeColor = op.isRunning ? UITheme::COLOR_ORANGE : (op.success ? UITheme::COLOR_GREEN : UITheme::COLOR_RED);

    if (UITheme::beginCard("OpCard_Status", op.moduleName.c_str(), statusBadge, badgeColor)) {
        ImGui::Columns(2, nullptr, false);

        UITheme::renderWrappedText("Operation Type:", UITheme::COLOR_TEXT_MUTED);
        UITheme::renderWrappedText(op.operationType.c_str(), UITheme::COLOR_TEXT_PRIMARY);
        ImGui::Spacing();
        UITheme::renderWrappedText("Target Source:", UITheme::COLOR_TEXT_MUTED);
        UITheme::renderWrappedText(op.targetSource.c_str(), UITheme::COLOR_TEXT_PRIMARY);

        ImGui::NextColumn();

        if (!op.destination.empty()) {
            UITheme::renderWrappedText("Destination Path:", UITheme::COLOR_TEXT_MUTED);
            UITheme::renderWrappedText(op.destination.c_str(), UITheme::COLOR_TEXT_PRIMARY);
            ImGui::Spacing();
        }

        float elapsed = op.getElapsedSeconds();
        int mins = static_cast<int>(elapsed) / 60;
        int secs = static_cast<int>(elapsed) % 60;
        std::stringstream ss;
        ss << std::setfill('0') << std::setw(2) << mins << ":"
           << std::setfill('0') << std::setw(2) << secs;

        UITheme::renderWrappedText("Elapsed Time:", UITheme::COLOR_TEXT_MUTED);
        UITheme::renderWrappedText(ss.str().c_str(), UITheme::COLOR_ORANGE);

        ImGui::Columns(1);
        ImGui::Spacing();

        // Progress Bar
        std::stringstream prgStr;
        prgStr << std::fixed << std::setprecision(1) << (op.progress * 100.0f) << "% — " << op.statusText;
        UITheme::renderProgressBar(op.progress, prgStr.str().c_str(), op.subStatusText.c_str());

        ImGui::Spacing();

        // Action shortcuts
        if (!op.isRunning) {
            if (op.moduleName.find("Carver") != std::string::npos || op.moduleName.find("Recovery") != std::string::npos) {
                if (UITheme::renderPrimaryButton("View Recovered Files Registry ->", ImVec2(260, 34))) {
                    ctx.activeTab = ModuleTab::RECOVERED_FILES;
                }
                ImGui::SameLine();
            }

            if (UITheme::renderSecondaryButton("View Audit Journal ->", ImVec2(200, 34))) {
                ctx.activeTab = ModuleTab::AUDIT_LOG;
            }

            ImGui::SameLine();
            if (UITheme::renderGhostButton("Clear Monitor", ImVec2(120, 34))) {
                op.hasFinished = false;
            }
        }
    }
    UITheme::endCard();

    // Event Log Card
    if (UITheme::beginCard("OpCard_Log", "Operation Event Log", "LIVE CONSOLE", UITheme::COLOR_BLUE)) {
        ImGui::PushStyleColor(ImGuiCol_ChildBg, UITheme::COLOR_CREAM_INSET);
        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 8.0f);
        ImGui::BeginChild("LogConsole", ImVec2(0, 320), true);

        if (UITheme::fontMono) ImGui::PushFont(UITheme::fontMono);

        for (const auto& line : op.logEvents) {
            if (line.find("[Result]") != std::string::npos || line.find("SUCCESS") != std::string::npos) {
                ImGui::TextColored(UITheme::COLOR_GREEN, "%s", line.c_str());
            } else if (line.find("FAILED") != std::string::npos || line.find("Error") != std::string::npos) {
                ImGui::TextColored(UITheme::COLOR_RED, "%s", line.c_str());
            } else {
                ImGui::TextColored(UITheme::COLOR_TEXT_PRIMARY, "%s", line.c_str());
            }
        }

        if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) {
            ImGui::SetScrollHereY(1.0f);
        }

        if (UITheme::fontMono) ImGui::PopFont();

        ImGui::EndChild();
        ImGui::PopStyleVar();
        ImGui::PopStyleColor();
    }
    UITheme::endCard();
}

void ViewOperationProgress::renderIdleState() {
    auto& ctx = AppContext::getInstance();

    if (UITheme::beginCard("OpCard_Idle", "No Active Foreground Operations", "SYSTEM IDLE", UITheme::COLOR_GREEN)) {
        ImGui::TextColored(UITheme::COLOR_TEXT_SECONDARY,
            "The ForensiVault engine is currently in standby mode. All background worker threads are idle.");
        ImGui::Spacing();
        ImGui::Text("To start a forensic operation, select one of the core modules from the sidebar:");
        ImGui::Spacing();

        ImGui::BulletText("Filesystem Recovery: Parse FAT32 directory tables, exFAT streams, or NTFS $MFT records.");
        ImGui::BulletText("Raw File Carving: Scan binary streams for file headers (PDF, Office, Images, Audio/Video).");
        ImGui::BulletText("Drive Sanitizer: Execute certified block-level sanitization across disk images or media.");
        ImGui::BulletText("File Eraser: Securely sanitize files and directory trees with metadata cleansing.");

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        if (UITheme::renderPrimaryButton("Go to Filesystem Recovery", ImVec2(220, 34))) {
            ctx.activeTab = ModuleTab::FS_RECOVERY;
        }
        ImGui::SameLine();
        if (UITheme::renderSecondaryButton("Go to Raw File Carving", ImVec2(200, 34))) {
            ctx.activeTab = ModuleTab::FILE_CARVER;
        }
    }
    UITheme::endCard();
}

} // namespace forensivault::gui
