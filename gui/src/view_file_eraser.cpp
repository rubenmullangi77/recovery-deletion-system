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

namespace {

uint64_t computeDirectoryRecursiveSize(const fs::path& dirPath) {
    uint64_t total = 0;
    std::error_code ec;
    if (!fs::exists(dirPath, ec) || !fs::is_directory(dirPath, ec)) return 0;
    for (const auto& entry : fs::recursive_directory_iterator(dirPath, fs::directory_options::skip_permission_denied, ec)) {
        if (!entry.is_directory(ec)) {
            total += entry.file_size(ec);
        }
    }
    return total;
}

} // anonymous namespace

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
        bool browseFileClicked = false, browseDirClicked = false;
        UITheme::renderInputWithTwoButtons("##TargetPath", targetPathBuffer_, sizeof(targetPathBuffer_),
                                           "Browse File...", 130.0f, &browseFileClicked,
                                           "Browse Folder...", 130.0f, &browseDirClicked);

        bool textChanged = false;
        if (browseFileClicked) {
            std::string selected = FileDialog::openFile("Select File to Sanitize");
            if (!selected.empty()) {
                std::strncpy(targetPathBuffer_, selected.c_str(), sizeof(targetPathBuffer_) - 1);
                textChanged = true;
            }
        }
        if (browseDirClicked) {
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
                            item.sizeBytes = item.isDir ? computeDirectoryRecursiveSize(entry.path()) : fs::file_size(entry.path(), ec);
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

            ImGuiTableFlags tblFlags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable;
            if (dirItems_.size() > 20) tblFlags |= ImGuiTableFlags_ScrollY;
            float tableH = (dirItems_.size() > 20) ? 420.0f : 0.0f;

            if (ImGui::BeginTable("DirItemsTable", 4, tblFlags, ImVec2(0, tableH))) {
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
                    ImGui::Text("%s", UITheme::formatByteSize(dirItems_[i].sizeBytes).c_str());
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
        ImGui::Spacing();

        int methodIdx = static_cast<int>(selectedMethod_);
        ImGui::RadioButton("NIST SP 800-88 Rev 1 Clear (Single-Pass 0x00) [Standard]", &methodIdx, 0);
        ImGui::Spacing();
        ImGui::RadioButton("DoD 5220.22-M 3-Pass (0x00, 0xFF, PRNG)", &methodIdx, 1);
        ImGui::Spacing();
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
        UITheme::renderMetricTile("Total Payload", UITheme::formatByteSize(previewReport_.totalBytes).c_str(), "Unallocated blocks", UITheme::COLOR_ORANGE, -1);

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
    uint64_t erasedFiles = 0;
    uint64_t erasedDirs = 0;
    uint64_t erasedBytes = 0;
    int passes = 0;
    std::string sig;
    std::vector<std::string> errs;

    {
        std::lock_guard<std::mutex> lock(resultsMutex_);
        erasedFiles = totalErasedFiles_;
        erasedDirs = totalErasedDirs_;
        erasedBytes = totalErasedBytes_;
        passes = maxPassesCompleted_;
        sig = lastAuditSignature_;
        errs = executionErrors_;
    }

    if (UITheme::beginCard("ResultsCard", "Sanitization Execution Summary",
                           errs.empty() ? "COMPLETED & VERIFIED" : "WARNINGS DETECTED",
                           errs.empty() ? UITheme::COLOR_GREEN : UITheme::COLOR_RED)) {
        if (errs.empty()) {
            UITheme::renderSuccessBanner("All targeted data blocks overwritten and directory metadata entries scrambled.");
        } else {
            std::string errSummary = std::to_string(errs.size()) + " target(s) encountered errors.";
            UITheme::renderDangerBanner(errSummary.c_str());
        }

        ImGui::Columns(3, nullptr, false);
        UITheme::renderWrappedText("Files Erased:", UITheme::COLOR_TEXT_MUTED);
        UITheme::renderWrappedFormatted(UITheme::COLOR_TEXT_PRIMARY, "%llu files", static_cast<unsigned long long>(erasedFiles));
        ImGui::Spacing();
        UITheme::renderWrappedText("Folders Unlinked:", UITheme::COLOR_TEXT_MUTED);
        UITheme::renderWrappedFormatted(UITheme::COLOR_TEXT_PRIMARY, "%llu dirs", static_cast<unsigned long long>(erasedDirs));

        ImGui::NextColumn();
        UITheme::renderWrappedText("Bytes Cleared:", UITheme::COLOR_TEXT_MUTED);
        UITheme::renderWrappedFormatted(UITheme::COLOR_TEXT_PRIMARY, "%s", UITheme::formatByteSize(erasedBytes).c_str());
        ImGui::Spacing();
        UITheme::renderWrappedText("Passes Completed:", UITheme::COLOR_TEXT_MUTED);
        UITheme::renderWrappedFormatted(UITheme::COLOR_TEXT_PRIMARY, "%d passes", passes);

        ImGui::NextColumn();
        if (!sig.empty()) {
            UITheme::renderWrappedText("Audit Record:", UITheme::COLOR_TEXT_MUTED);
            UITheme::renderWrappedText("[LOGGED IN AUDIT CHAIN]", UITheme::COLOR_GREEN);
            ImGui::Spacing();
            UITheme::renderWrappedFormatted(UITheme::COLOR_TEXT_MUTED, "Sig: %s...", sig.substr(0, 16).c_str());
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
    ImGui::SetNextWindowSizeConstraints(ImVec2(480, 240), ImVec2(720, 800));

    if (ImGui::BeginPopupModal("Permanent Data Eradication Warning", &showConfirmModal_, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::TextColored(UITheme::COLOR_RED, "CRITICAL WARNING: IRREVERSIBLE FILE SANITIZATION");
        ImGui::Separator();
        ImGui::Spacing();
        UITheme::renderWrappedText("The selected data will be overwritten with certified multi-pass patterns and renamed with 3 passes of randomized tokens before deletion. "
                           "Recovery by forensic software or laboratory physical carving will be mathematically impossible.", UITheme::COLOR_TEXT_SECONDARY);
        ImGui::Spacing();
        UITheme::renderWrappedFormatted(UITheme::COLOR_TEXT_PRIMARY, "Target: %s", targetPathBuffer_);
        ImGui::Spacing();
        ImGui::TextColored(UITheme::COLOR_TEXT_PRIMARY, "Type 'DESTROY' in uppercase to authorize permanent erasure:");

        ImGui::SetNextItemWidth(-1);
        ImGui::InputText("##DestroyConfirm", confirmInputBuffer_, sizeof(confirmInputBuffer_));

        bool matches = (std::strcmp(confirmInputBuffer_, "DESTROY") == 0);

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        if (!matches) ImGui::BeginDisabled();

        if (UITheme::renderDestructiveButton("PERMANENTLY DESTROY DATA", ImVec2(240, 38))) {
            showConfirmModal_ = false;
            hasFinishedResult_.store(false);
            {
                std::lock_guard<std::mutex> lock(resultsMutex_);
                executionErrors_.clear();
                totalErasedFiles_ = 0;
                totalErasedDirs_ = 0;
                totalErasedBytes_ = 0;
                maxPassesCompleted_ = 0;
                lastAuditSignature_.clear();
            }

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
                uint64_t erasedFilesAcc = 0;
                uint64_t erasedDirsAcc = 0;
                uint64_t erasedBytesAcc = 0;
                int maxPassesAcc = 0;
                std::string lastSigAcc;
                std::vector<std::string> errsAcc;

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
                        erasedFilesAcc += res.filesErased;
                        erasedDirsAcc += res.directoriesErased;
                        erasedBytesAcc += res.bytesErased;
                        maxPassesAcc = std::max(maxPassesAcc, res.passesCompleted);
                        lastSigAcc = res.auditSignature;
                    } else {
                        errsAcc.push_back(targetItem.filename().string() + ": " + res.errorMessage);
                    }
                }

                {
                    std::lock_guard<std::mutex> lock(resultsMutex_);
                    totalErasedFiles_ = erasedFilesAcc;
                    totalErasedDirs_ = erasedDirsAcc;
                    totalErasedBytes_ = erasedBytesAcc;
                    maxPassesCompleted_ = maxPassesAcc;
                    lastAuditSignature_ = lastSigAcc;
                    executionErrors_ = errsAcc;
                }

                hasFinishedResult_.store(true);
                AppContext::getInstance().totalFilesErased += erasedFilesAcc;

                bool allOk = errsAcc.empty();
                std::string summary = "Erased " + std::to_string(erasedFilesAcc) + " files (" +
                                      UITheme::formatByteSize(erasedBytesAcc) + ").";
                AppContext::getInstance().currentOperation.finish(allOk, summary);

                if (allOk) {
                    AppContext::getInstance().postNotification(
                        Notification::Type::SUCCESS, "Sanitization Complete", summary);
                } else {
                    AppContext::getInstance().postNotification(
                        Notification::Type::FAILURE, "Sanitization Errors",
                        std::to_string(errsAcc.size()) + " target(s) failed.");
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
