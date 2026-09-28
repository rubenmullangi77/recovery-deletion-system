#include "view_carver.hpp"
#include "ui_theme.hpp"
#include "file_dialog.hpp"
#include "app_context.hpp"

#include <imgui.h>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <set>
#include <filesystem>

namespace fs = std::filesystem;

namespace forensivault::gui {

ViewCarver::ViewCarver() {
    std::memset(imagePathBuffer_, 0, sizeof(imagePathBuffer_));
    std::strncpy(outputDirBuffer_, "recovered/carved", sizeof(outputDirBuffer_) - 1);
    std::memset(searchFilterBuffer_, 0, sizeof(searchFilterBuffer_));
}

void ViewCarver::render() {
    UITheme::renderCardHeader("ADVANCED RAW DATA CARVER",
                              "Deep Read-Only Structural Boundary Extraction from Raw Streams, Binary Dumps & Unallocated Clusters");

    renderInputs();

    if (taskRunner_.isRunning()) {
        renderProgress();
    }

    if (hasResult_) {
        renderSummary();
        renderCarvedTable();
    }
}

void ViewCarver::renderInputs() {
    if (UITheme::beginCard("CarverInputCard", "Evidence Source & Target Configuration", "CONFIGURATION", UITheme::COLOR_BLUE)) {
        ImGui::Text("Evidence Source File / Image (.img, .dd, .raw, .pdf, .docx, or any binary dump):");
        ImGui::PushItemWidth(-140);
        ImGui::InputText("##ImagePath", imagePathBuffer_, sizeof(imagePathBuffer_));
        ImGui::PopItemWidth();

        ImGui::SameLine();
        if (UITheme::renderSecondaryButton("Browse Source...", ImVec2(130, 32))) {
            std::string selected = FileDialog::openFile("Select Evidence Source File", "All Files (*.*)", "*.*");
            if (!selected.empty()) {
                std::strncpy(imagePathBuffer_, selected.c_str(), sizeof(imagePathBuffer_) - 1);
            }
        }

        ImGui::Spacing();
        ImGui::Text("Extraction Destination Directory:");
        ImGui::PushItemWidth(-140);
        ImGui::InputText("##OutputDir", outputDirBuffer_, sizeof(outputDirBuffer_));
        ImGui::PopItemWidth();

        ImGui::SameLine();
        if (UITheme::renderSecondaryButton("Browse Folder...", ImVec2(130, 32))) {
            std::string selected = FileDialog::openFolder("Select Output Recovery Folder");
            if (!selected.empty()) {
                std::strncpy(outputDirBuffer_, selected.c_str(), sizeof(outputDirBuffer_) - 1);
            }
        }

        ImGui::Spacing();
        ImGui::Text("Extraction Confidence Threshold:");
        ImGui::SliderFloat("##MinConfidence", &minConfidence_, 0.0f, 100.0f, "%.0f%%");
        ImGui::SameLine();
        ImGui::TextColored(UITheme::COLOR_TEXT_MUTED, "(Lower extracts more candidates; higher guarantees format integrity)");

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        bool canCarve = strlen(imagePathBuffer_) > 0 && fs::exists(imagePathBuffer_) && !taskRunner_.isRunning();

        if (!canCarve) ImGui::BeginDisabled();

        if (UITheme::renderPrimaryButton("Start Deep File Carving (Read-Only)...", ImVec2(320, 38))) {
            hasResult_ = false;
            std::string img = imagePathBuffer_;
            std::string out = outputDirBuffer_;
            double conf = static_cast<double>(minConfidence_);

            AppContext::getInstance().currentOperation.start(
                "Raw Data Carver", "Deep Boundary Carving", img, out);

            taskRunner_.run([this, img, out, conf]() {
                auto cb = [this](const forensivault::api::CarveProgress& prg) {
                    float frac = static_cast<float>(prg.percentComplete / 100.0);
                    std::ostringstream ss;
                    ss << std::fixed << std::setprecision(1) << prg.percentComplete << "% Scanned";
                    std::ostringstream sub;
                    sub << prg.filesDiscovered << " candidate artifacts validated...";
                    taskRunner_.setProgress(frac, ss.str(), sub.str());
                    AppContext::getInstance().currentOperation.update(frac, ss.str(), sub.str());
                };

                finalResult_ = forensivault::api::CarverAPI::carve(img, out, conf, cb);
                hasResult_ = true;

                if (finalResult_.success) {
                    // Register carved files in global registry
                    for (const auto& item : finalResult_.carvedFiles) {
                        std::string filename = fs::path(item.recoveredFilePath).filename().string();
                        if (filename.empty()) {
                            std::stringstream ss;
                            ss << "carved_0x" << std::hex << item.offset << "." << item.fileType;
                            filename = ss.str();
                        }
                        std::string confLevel = (item.confidenceScore >= 85.0) ? "HIGH" :
                                                ((item.confidenceScore >= 60.0) ? "MEDIUM" :
                                                ((item.confidenceScore >= 30.0) ? "LOW" : "UNCERTAIN"));
                        AppContext::getInstance().registerCarvedFile(
                            filename, item.recoveredFilePath, item.fileType, item.offset,
                            item.lengthBytes, item.confidenceScore, confLevel, item.sha256);
                    }

                    std::string summary = "Successfully carved " + std::to_string(finalResult_.filesSuccessfullyCarved) + " files.";
                    AppContext::getInstance().currentOperation.finish(true, summary);
                    AppContext::getInstance().postNotification(
                        Notification::Type::SUCCESS, "Carving Complete", summary);
                } else {
                    AppContext::getInstance().currentOperation.finish(false, finalResult_.errorMessage);
                    AppContext::getInstance().postNotification(
                        Notification::Type::FAILURE, "Carving Failed",
                        finalResult_.errorMessage);
                }
            });
        }

        if (!canCarve) ImGui::EndDisabled();
    }
    UITheme::endCard();
}

void ViewCarver::renderProgress() {
    if (UITheme::beginCard("CarverProgressCard", "Carving Engine Execution (Read-Only Mode)", "STREAM SCAN", UITheme::COLOR_BLUE)) {
        UITheme::renderProgressBar(taskRunner_.getProgress(), taskRunner_.getStatusText().c_str(), taskRunner_.getSubStatusText().c_str());
    }
    UITheme::endCard();
}

void ViewCarver::renderSummary() {
    if (UITheme::beginCard("CarverSummaryCard", "Carving Session Results",
                           finalResult_.success ? "SESSION COMPLETE" : "ERRORS DETECTED",
                           finalResult_.success ? UITheme::COLOR_GREEN : UITheme::COLOR_RED)) {
        if (finalResult_.success) {
            ImGui::Columns(4, nullptr, false);

            std::string discStr = std::to_string(finalResult_.signaturesDiscovered);
            UITheme::renderMetricTile("Signatures Found", discStr.c_str(), "Signatures identified", UITheme::COLOR_BLUE, -1);

            ImGui::NextColumn();

            std::string carvedStr = std::to_string(finalResult_.filesSuccessfullyCarved);
            UITheme::renderMetricTile("Carved & Validated", carvedStr.c_str(), "Boundary resolved", UITheme::COLOR_GREEN, -1);

            ImGui::NextColumn();

            uint64_t totalBytes = 0;
            for (const auto& item : finalResult_.carvedFiles) {
                totalBytes += item.lengthBytes;
            }
            double mb = static_cast<double>(totalBytes) / (1024.0 * 1024.0);
            std::stringstream ssMb;
            ssMb << std::fixed << std::setprecision(2) << mb << " MB";
            UITheme::renderMetricTile("Extracted Payload", ssMb.str().c_str(), "Written to disk", UITheme::COLOR_ORANGE, -1);

            ImGui::NextColumn();

            std::stringstream ssDur;
            ssDur << std::fixed << std::setprecision(2) << finalResult_.durationSeconds << " s";
            UITheme::renderMetricTile("Scan Duration", ssDur.str().c_str(), "Read-only throughput", UITheme::COLOR_TEXT_PRIMARY, -1);

            ImGui::Columns(1);
        } else {
            UITheme::renderDangerBanner(finalResult_.errorMessage.c_str());
        }
    }
    UITheme::endCard();
}

void ViewCarver::renderCarvedTable() {
    if (finalResult_.carvedFiles.empty()) return;

    if (UITheme::beginCard("CarvedArtifactsCard", "Extracted Artifacts Table", "DISCOVERED FILES", UITheme::COLOR_BLUE)) {
        ImGui::Text("Filter Extracted Files:");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(250);
        ImGui::InputText("##CarverFilter", searchFilterBuffer_, sizeof(searchFilterBuffer_));

        ImGui::SameLine(ImGui::GetWindowWidth() - 250);
        if (UITheme::renderSecondaryButton("Open Output Folder", ImVec2(180, 30))) {
            FileDialog::openFolderInExplorer(outputDirBuffer_);
        }

        std::string filterLower = searchFilterBuffer_;
        std::transform(filterLower.begin(), filterLower.end(), filterLower.begin(), ::tolower);

        if (ImGui::BeginTable("CarverTable", 6, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY, ImVec2(0, 320))) {
            ImGui::TableSetupColumn("Filename", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 80.0f);
            ImGui::TableSetupColumn("Offset (Hex)", ImGuiTableColumnFlags_WidthFixed, 120.0f);
            ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 90.0f);
            ImGui::TableSetupColumn("Confidence", ImGuiTableColumnFlags_WidthFixed, 140.0f);
            ImGui::TableSetupColumn("SHA-256 Hash", ImGuiTableColumnFlags_WidthFixed, 180.0f);
            ImGui::TableHeadersRow();

            for (const auto& item : finalResult_.carvedFiles) {
                std::string fname = fs::path(item.recoveredFilePath).filename().string();
                if (fname.empty()) {
                    std::stringstream ss;
                    ss << "carved_0x" << std::hex << item.offset << "." << item.fileType;
                    fname = ss.str();
                }

                if (!filterLower.empty()) {
                    std::string fnLower = fname;
                    std::transform(fnLower.begin(), fnLower.end(), fnLower.begin(), ::tolower);
                    if (fnLower.find(filterLower) == std::string::npos &&
                        item.fileType.find(filterLower) == std::string::npos) {
                        continue;
                    }
                }

                ImGui::TableNextRow();

                ImGui::TableSetColumnIndex(0);
                ImGui::Text("%s", fname.c_str());

                ImGui::TableSetColumnIndex(1);
                ImGui::TextColored(UITheme::COLOR_ORANGE, "%s", item.fileType.c_str());

                ImGui::TableSetColumnIndex(2);
                if (UITheme::fontMono) ImGui::PushFont(UITheme::fontMono);
                std::stringstream ss;
                ss << "0x" << std::hex << std::uppercase << item.offset;
                ImGui::Text("%s", ss.str().c_str());
                if (UITheme::fontMono) ImGui::PopFont();

                ImGui::TableSetColumnIndex(3);
                if (item.lengthBytes < 1024) {
                    ImGui::Text("%llu B", static_cast<unsigned long long>(item.lengthBytes));
                } else if (item.lengthBytes < 1024 * 1024) {
                    ImGui::Text("%.1f KB", item.lengthBytes / 1024.0);
                } else {
                    ImGui::Text("%.2f MB", item.lengthBytes / (1024.0 * 1024.0));
                }

                ImGui::TableSetColumnIndex(4);
                std::string confLevel = (item.confidenceScore >= 85.0) ? "HIGH" :
                                        ((item.confidenceScore >= 60.0) ? "MEDIUM" :
                                        ((item.confidenceScore >= 30.0) ? "LOW" : "UNCERTAIN"));
                std::stringstream confSs;
                confSs << std::fixed << std::setprecision(0) << item.confidenceScore << "% (" << confLevel << ")";
                ImVec4 cCol = UITheme::COLOR_GREEN;
                if (confLevel == "MEDIUM") cCol = UITheme::COLOR_YELLOW;
                else if (confLevel == "LOW" || confLevel == "UNCERTAIN") cCol = UITheme::COLOR_RED;
                UITheme::renderBadge(confSs.str().c_str(), cCol);

                ImGui::TableSetColumnIndex(5);
                if (UITheme::fontMono) ImGui::PushFont(UITheme::fontMono);
                if (!item.sha256.empty()) {
                    std::string shortH = (item.sha256.size() > 16) ? item.sha256.substr(0, 16) + "..." : item.sha256;
                    ImGui::Text("%s", shortH.c_str());
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
