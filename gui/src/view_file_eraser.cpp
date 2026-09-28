#include "view_file_eraser.hpp"
#include "ui_theme.hpp"
#include "file_dialog.hpp"
#include "app_context.hpp"
#include <forensivault/core/platform.hpp>

#include <imgui.h>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace fs = std::filesystem;

namespace forensivault::gui {

ViewFileEraser::ViewFileEraser() {
    std::memset(targetPathBuffer_, 0, sizeof(targetPathBuffer_));
    std::memset(confirmInputBuffer_, 0, sizeof(confirmInputBuffer_));
}

void ViewFileEraser::render() {
    UITheme::renderCardHeader("SECURE FILE & FOLDER SANITIZER",
                              "Certified Cluster-Aligned Data Overwrites with 3-Pass Metadata Unallocation (NIST SP 800-88 R1 & DoD 5220.22-M)");

    renderTargetSelection();

    if (isSystemProtected_) {
        std::string warn = "CRITICAL SAFETY INTERLOCK ACTIVE: " + protectionReason_ +
                           " ForensiVault permanently protects the operating system, root, and internal boot volumes.";
        UITheme::renderDangerBanner(warn.c_str());
    }

    if (isDirectory_ && !dirItems_.empty()) {
        renderDirectoryInspector();
    }

    renderActionControls();

    if (hasPreview_) {
        renderPreviewCard();
    }

    if (taskRunner_.isRunning()) {
        renderProgressCard();
    }

    if (hasFinishedResult_) {
        renderResultsCard();
    }

    renderConfirmationModal();
}

void ViewFileEraser::renderTargetSelection() {
    if (UITheme::beginCard("FileTargetCard", "Target File or Directory Selection", "TARGET PATH", UITheme::COLOR_ORANGE)) {
        ImGui::Text("Specify an individual file or directory tree for cryptographic sanitization:");
        ImGui::PushItemWidth(-260);
        bool textChanged = ImGui::InputText("##TargetPath", targetPathBuffer_, sizeof(targetPathBuffer_));
        ImGui::PopItemWidth();

        ImGui::SameLine();
        if (UITheme::renderSecondaryButton("Browse File...", ImVec2(120, 32))) {
            std::string selected = FileDialog::openFile("Select File to Sanitize");
            if (!selected.empty()) {
                std::strncpy(targetPathBuffer_, selected.c_str(), sizeof(targetPathBuffer_) - 1);
                textChanged = true;
            }
        }

        ImGui::SameLine();
        if (UITheme::renderSecondaryButton("Browse Folder...", ImVec2(120, 32))) {
            std::string selected = FileDialog::openFolder("Select Directory to Sanitize");
            if (!selected.empty()) {
                std::strncpy(targetPathBuffer_, selected.c_str(), sizeof(targetPathBuffer_) - 1);
                textChanged = true;
            }
        }

        if (textChanged || currentInspectedPath_ != targetPathBuffer_) {
            currentInspectedPath_ = targetPathBuffer_;
            hasPreview_ = false;
            dirItems_.clear();
            isSystemProtected_ = false;

            fs::path p(targetPathBuffer_);
            std::error_code ec;
            if (fs::exists(p, ec)) {
                if (forensivault::core::Platform::isRootOrSystemPath(p) ||
                    forensivault::core::Platform::isMainSystemDrive(p)) {
                    isSystemProtected_ = true;
                    protectionReason_ = "Target is OS root or main system drive (" + p.string() + ").";
                }

                isDirectory_ = fs::is_directory(p, ec);
                if (isDirectory_) {
                    try {
                        for (const auto& entry : fs::directory_iterator(p)) {
                            DirItem item;
                            item.path = entry.path();
                            item.filename = entry.path().filename().string();
                            item.isDir = fs::is_directory(entry.path(), ec);
                            item.sizeBytes = item.isDir ? 0 : fs::file_size(entry.path(), ec);
                            item.selected = true;
                            dirItems_.push_back(item);
                        }
                        std::sort(dirItems_.begin(), dirItems_.end(), [](const DirItem& a, const DirItem& b) {
                            return a.filename < b.filename;
                        });
                    } catch (...) {
                    }
                }
            } else {
                isDirectory_ = false;
            }
        }
    }
    UITheme::endCard();
}

void ViewFileEraser::renderDirectoryInspector() {
    if (UITheme::beginCard("DirInspectCard", "Directory Items Selection", "BATCH ITEMS", UITheme::COLOR_BLUE)) {
        ImGui::Checkbox("Sanitize Entire Directory Recursively (Default)", &sanitizeEntireDirectory_);

        if (!sanitizeEntireDirectory_) {
            ImGui::SameLine();
            if (ImGui::SmallButton("Select All")) {
                for (auto& item : dirItems_) item.selected = true;
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("Deselect All")) {
                for (auto& item : dirItems_) item.selected = false;
            }

            if (ImGui::BeginTable("DirItemsTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, 160))) {
                ImGui::TableSetupColumn("Select", ImGuiTableColumnFlags_WidthFixed, 60.0f);
                ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 70.0f);
                ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                ImGui::TableHeadersRow();

                for (size_t i = 0; i < dirItems_.size(); ++i) {
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    std::string cbId = "##item_" + std::to_string(i);
                    ImGui::Checkbox(cbId.c_str(), &dirItems_[i].selected);

                    ImGui::TableSetColumnIndex(1);
                    ImGui::Text("%s", dirItems_[i].filename.c_str());

                    ImGui::TableSetColumnIndex(2);
                    if (dirItems_[i].isDir) {
                        UITheme::renderBadge("DIR", UITheme::COLOR_BLUE);
                    } else {
                        UITheme::renderBadge("FILE", UITheme::COLOR_ORANGE);
                    }

                    ImGui::TableSetColumnIndex(3);
                    if (!dirItems_[i].isDir) {
                        if (dirItems_[i].sizeBytes < 1024) {
                            ImGui::Text("%llu B", static_cast<unsigned long long>(dirItems_[i].sizeBytes));
                        } else if (dirItems_[i].sizeBytes < 1024 * 1024) {
                            ImGui::Text("%.1f KB", dirItems_[i].sizeBytes / 1024.0);
                        } else {
                            ImGui::Text("%.2f MB", dirItems_[i].sizeBytes / (1024.0 * 1024.0));
                        }
                    } else {
                        ImGui::TextDisabled("—");
                    }
                }
                ImGui::EndTable();
            }
        }
    }
    UITheme::endCard();
}

void ViewFileEraser::renderActionControls() {
    if (UITheme::beginCard("ActionCtrlCard", "Sanitization Strategy & Verification Preview", "CONFIG", UITheme::COLOR_ORANGE)) {
        ImGui::TextColored(UITheme::COLOR_TEXT_PRIMARY, "Certified Sanitization Algorithm:");
        int methodIdx = static_cast<int>(selectedMethod_);
        ImGui::RadioButton("NIST SP 800-88 Rev 1 Clear (Single-Pass 0x00) [Standard]", &methodIdx, 0);
        ImGui::SameLine();
        ImGui::RadioButton("DoD 5220.22-M 3-Pass (0x00, 0xFF, PRNG)", &methodIdx, 1);
        ImGui::SameLine();
        ImGui::RadioButton("Cryptographic PRNG Random Fill", &methodIdx, 2);
        selectedMethod_ = static_cast<forensivault::api::EraseMethod>(methodIdx);

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        bool canAct = strlen(targetPathBuffer_) > 0 && fs::exists(targetPathBuffer_) && !isSystemProtected_ && !taskRunner_.isRunning();

        if (!canAct) ImGui::BeginDisabled();

        if (UITheme::renderSecondaryButton("Generate Non-Destructive Preview", ImVec2(260, 36))) {
            hasPreview_ = false;
            std::string p = targetPathBuffer_;
            previewReport_ = forensivault::api::FileEraserAPI::preview(p);
            hasPreview_ = true;
        }

        ImGui::SameLine();

        if (UITheme::renderDestructiveButton("Execute Irreversible Erasure...", ImVec2(260, 36))) {
            showConfirmModal_ = true;
            std::memset(confirmInputBuffer_, 0, sizeof(confirmInputBuffer_));
        }

        if (!canAct) ImGui::EndDisabled();
    }
    UITheme::endCard();
}

void ViewFileEraser::renderPreviewCard() {
    bool safe = !previewReport_.isRootOrSystemProtected;
    if (UITheme::beginCard("PreviewReportCard", "Non-Destructive Sanitization Preview",
                           safe ? "SAFETY CLEARED" : "RESTRICTED",
                           safe ? UITheme::COLOR_GREEN : UITheme::COLOR_RED)) {
        ImGui::Columns(4, nullptr, false);

        std::string totalFilesStr = std::to_string(previewReport_.totalFiles);
        UITheme::renderMetricTile("Total Files", totalFilesStr.c_str(), "Data forks", UITheme::COLOR_ORANGE, -1);

        ImGui::NextColumn();

        std::string totalDirsStr = std::to_string(previewReport_.totalDirectories);
        UITheme::renderMetricTile("Total Folders", totalDirsStr.c_str(), "Directory entries", UITheme::COLOR_BLUE, -1);

        ImGui::NextColumn();

        double mb = static_cast<double>(previewReport_.totalBytes) / (1024.0 * 1024.0);
        std::stringstream ssMb;
        ssMb << std::fixed << std::setprecision(2) << mb << " MB";
        UITheme::renderMetricTile("Total Payload", ssMb.str().c_str(), "Unallocated blocks", UITheme::COLOR_ORANGE, -1);

        ImGui::NextColumn();

        int passes = (selectedMethod_ == forensivault::api::EraseMethod::DOD_5220_22_M) ? 3 : 1;
        std::string passesStr = std::to_string(passes) + " Passes";
        UITheme::renderMetricTile("Overwrites", passesStr.c_str(), "Flush buffers", UITheme::COLOR_GREEN, -1);

        ImGui::Columns(1);
    }
    UITheme::endCard();
}

void ViewFileEraser::renderProgressCard() {
    if (UITheme::beginCard("ProgressCard", "Erasure Engine Execution", "ACTIVE WORKER", UITheme::COLOR_ORANGE)) {
        UITheme::renderProgressBar(taskRunner_.getProgress(), taskRunner_.getStatusText().c_str(), taskRunner_.getSubStatusText().c_str());
    }
    UITheme::endCard();
}

void ViewFileEraser::renderResultsCard() {
    if (UITheme::beginCard("ResultsCard", "Sanitization Execution Summary",
                           executionErrors_.empty() ? "COMPLETED & VERIFIED" : "WARNINGS DETECTED",
                           executionErrors_.empty() ? UITheme::COLOR_GREEN : UITheme::COLOR_RED)) {
        if (executionErrors_.empty()) {
            UITheme::renderSuccessBanner("All targeted data blocks overwritten and directory metadata entries scrambled.");
        } else {
            std::string errSummary = std::to_string(executionErrors_.size()) + " target(s) encountered errors.";
            UITheme::renderDangerBanner(errSummary.c_str());
        }

        ImGui::Columns(3, nullptr, false);
        ImGui::Text("Files Erased:       %llu", static_cast<unsigned long long>(totalErasedFiles_));
        ImGui::Text("Folders Unlinked:   %llu", static_cast<unsigned long long>(totalErasedDirs_));
        ImGui::NextColumn();
        double mb = static_cast<double>(totalErasedBytes_) / (1024.0 * 1024.0);
        ImGui::Text("Bytes Cleared:      %.2f MB", mb);
        ImGui::Text("Passes Completed:   %d", maxPassesCompleted_);
        ImGui::NextColumn();
        if (!lastAuditSignature_.empty()) {
            ImGui::Text("Audit Record:       [LOGGED]");
            ImGui::TextDisabled("Signature: %s", lastAuditSignature_.substr(0, 16).c_str());
        }
        ImGui::Columns(1);
    }
    UITheme::endCard();
}

void ViewFileEraser::renderConfirmationModal() {
    if (showConfirmModal_) {
        ImGui::OpenPopup("Permanent Data Eradication Warning");
    }

    ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(540, 310));

    if (ImGui::BeginPopupModal("Permanent Data Eradication Warning", &showConfirmModal_, ImGuiWindowFlags_NoResize)) {
        ImGui::TextColored(UITheme::COLOR_RED, "CRITICAL WARNING: IRREVERSIBLE FILE SANITIZATION");
        ImGui::Separator();
        ImGui::Spacing();
        ImGui::TextWrapped("The selected data will be overwritten with certified multi-pass patterns and renamed with 3 passes of randomized tokens before deletion. "
                           "Recovery by forensic software or laboratory physical carving will be mathematically impossible.");
        ImGui::Spacing();
        ImGui::Text("Target: %s", targetPathBuffer_);
        ImGui::Spacing();
        ImGui::Text("Type 'DESTROY' in uppercase to authorize permanent erasure:");

        ImGui::InputText("##DestroyConfirm", confirmInputBuffer_, sizeof(confirmInputBuffer_));

        bool matches = (std::strcmp(confirmInputBuffer_, "DESTROY") == 0);

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        if (!matches) ImGui::BeginDisabled();

        if (UITheme::renderDestructiveButton("PERMANENTLY DESTROY DATA", ImVec2(240, 38))) {
            showConfirmModal_ = false;
            hasFinishedResult_ = false;
            executionErrors_.clear();
            totalErasedFiles_ = 0;
            totalErasedDirs_ = 0;
            totalErasedBytes_ = 0;
            maxPassesCompleted_ = 0;

            std::vector<fs::path> targetsToErase;
            if (isDirectory_ && !sanitizeEntireDirectory_) {
                for (const auto& item : dirItems_) {
                    if (item.selected) {
                        targetsToErase.push_back(item.path);
                    }
                }
            } else {
                targetsToErase.push_back(fs::path(targetPathBuffer_));
            }

            auto method = selectedMethod_;
            std::string targetSource = targetPathBuffer_;

            // Register with global operation monitor
            AppContext::getInstance().currentOperation.start(
                "File & Folder Eraser",
                (method == forensivault::api::EraseMethod::NIST_800_88_CLEAR ? "NIST SP 800-88 Clear" : "DoD 5220.22-M 3-Pass"),
                targetSource, "");

            taskRunner_.run([this, targetsToErase, method, targetSource]() {
                size_t totalTargets = targetsToErase.size();
                for (size_t targetIdx = 0; targetIdx < totalTargets; ++targetIdx) {
                    const auto& targetItem = targetsToErase[targetIdx];
                    std::error_code itemEc;
                    forensivault::api::EraseResult res;

                    auto progressCb = [this, targetIdx, totalTargets](const forensivault::api::EraseProgress& prg) {
                        float frac = static_cast<float>(prg.percentComplete / 100.0);
                        std::ostringstream ss;
                        ss << "Pass " << prg.currentPass << "/" << prg.totalPasses
                           << " (" << std::fixed << std::setprecision(1) << prg.percentComplete << "%)";
                        if (totalTargets > 1) {
                            ss << " [Item " << (targetIdx + 1) << "/" << totalTargets << "]";
                        }
                        taskRunner_.setProgress(frac, ss.str(), prg.currentPath);
                        AppContext::getInstance().currentOperation.update(frac, ss.str(), prg.currentPath);
                    };

                    if (fs::is_directory(targetItem, itemEc)) {
                        res = forensivault::api::FileEraserAPI::eraseDirectory(targetItem.string(), method, progressCb);
                    } else {
                        res = forensivault::api::FileEraserAPI::eraseFile(targetItem.string(), method, progressCb);
                    }

                    if (res.success) {
                        totalErasedFiles_ += res.filesErased;
                        totalErasedDirs_ += res.directoriesErased;
                        totalErasedBytes_ += res.bytesErased;
                        maxPassesCompleted_ = std::max(maxPassesCompleted_, res.passesCompleted);
                        lastAuditSignature_ = res.auditSignature;
                    } else {
                        executionErrors_.push_back(targetItem.filename().string() + ": " + res.errorMessage);
                    }
                }

                hasFinishedResult_ = true;
                AppContext::getInstance().totalFilesErased += totalErasedFiles_;

                bool allOk = executionErrors_.empty();
                std::string summary = "Erased " + std::to_string(totalErasedFiles_) + " files (" +
                                      std::to_string(totalErasedBytes_ / (1024 * 1024)) + " MB).";
                AppContext::getInstance().currentOperation.finish(allOk, summary);

                if (allOk) {
                    AppContext::getInstance().postNotification(
                        Notification::Type::SUCCESS, "Sanitization Complete", summary);
                } else {
                    AppContext::getInstance().postNotification(
                        Notification::Type::FAILURE, "Sanitization Errors",
                        std::to_string(executionErrors_.size()) + " target(s) failed.");
                }
            });
        }

        if (!matches) ImGui::EndDisabled();

        ImGui::SameLine();
        if (UITheme::renderSecondaryButton("Cancel", ImVec2(100, 38))) {
            showConfirmModal_ = false;
        }

        ImGui::EndPopup();
    }
}

} // namespace forensivault::gui
