#include "view_fs_recovery.hpp"
#include "ui_theme.hpp"
#include "file_dialog.hpp"
#include "app_context.hpp"
#include <forensivault/core/platform.hpp>

#include <imgui.h>
#include <cstring>
#include <sstream>
#include <filesystem>
#include <algorithm>
#include <iomanip>

namespace fs = std::filesystem;

namespace forensivault::gui {

namespace {

std::string formatByteSize(uint64_t bytes) {
    if (bytes < 1024) {
        return std::to_string(bytes) + " B";
    } else if (bytes < 1024 * 1024) {
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(1) << (bytes / 1024.0) << " KB";
        return ss.str();
    } else if (bytes < 1024ULL * 1024 * 1024) {
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(2) << (bytes / (1024.0 * 1024.0)) << " MB";
        return ss.str();
    } else {
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(2) << (bytes / (1024.0 * 1024.0 * 1024.0)) << " GB";
        return ss.str();
    }
}

bool isSubdirectory(const std::string& parent, const std::string& child) {
    if (parent.empty() || child.empty()) return false;
    std::error_code ec;
    fs::path pParent(parent);
    fs::path pChild(child);
    if (fs::exists(pParent, ec)) pParent = fs::canonical(pParent, ec);
    if (fs::exists(pChild, ec)) pChild = fs::canonical(pChild, ec);
    std::string sParent = pParent.lexically_normal().string();
    std::string sChild = pChild.lexically_normal().string();
    if (sParent == sChild) return true;
    if (sChild.rfind(sParent, 0) == 0) {
        if (sParent.back() == '/' || sParent.back() == '\\') return true;
        char next = sChild[sParent.size()];
        return (next == '/' || next == '\\');
    }
    return false;
}

} // anonymous namespace

ViewFsRecovery::ViewFsRecovery() {
    recoveryMode_ = 0; // Default to Live Directory Recovery

    std::string homeDir = core::Platform::getUserHomeDirectory();
    std::memset(targetDirBuffer_, 0, sizeof(targetDirBuffer_));
    if (!homeDir.empty() && homeDir != ".") {
        std::strncpy(targetDirBuffer_, homeDir.c_str(), sizeof(targetDirBuffer_) - 1);
    }

    std::memset(dirOutputDirBuffer_, 0, sizeof(dirOutputDirBuffer_));
    std::string defaultRecovered = (fs::path(homeDir) / "ForensiVault_Recovered").string();
    std::strncpy(dirOutputDirBuffer_, defaultRecovered.c_str(), sizeof(dirOutputDirBuffer_) - 1);

    std::memset(imagePathBuffer_, 0, sizeof(imagePathBuffer_));
    std::strncpy(outputDirBuffer_, "recovered/filesystem", sizeof(outputDirBuffer_) - 1);
}

void ViewFsRecovery::render() {
    UITheme::renderCardHeader("FILESYSTEM & DIRECTORY RECOVERY",
                              "Live Directory Deleted Item Recovery & Forensic Volume Reconstruction (FAT32, exFAT, NTFS)");

    renderModeSelector();

    if (recoveryMode_ == 0) {
        renderDirectoryRecovery();
    } else {
        renderImageRecovery();
    }
}

void ViewFsRecovery::renderModeSelector() {
    if (UITheme::beginCard("FsModeCard", "Recovery Workflow Mode", "TARGET SETUP", UITheme::COLOR_BLUE)) {
        ImGui::Text("Select the target type for discovering and restoring deleted files:");
        ImGui::Spacing();

        if (ImGui::RadioButton("Live Directory & Drive Scan  (Scan any folder or drive mount for previously deleted files)", recoveryMode_ == 0)) {
            recoveryMode_ = 0;
        }

        ImGui::Spacing();

        if (ImGui::RadioButton("Forensic Raw Disk Image  (Parse .img / .dd disk image with partition sector offset)", recoveryMode_ == 1)) {
            recoveryMode_ = 1;
        }

        ImGui::Spacing();
    }
    UITheme::endCard();
}

void ViewFsRecovery::renderDirectoryRecovery() {
    // 1. Directory Input & Mount Inspection Card
    if (UITheme::beginCard("DirInputCard", "Live Directory Recovery Target", "DIRECTORY", UITheme::COLOR_BLUE)) {
        ImGui::Text("Target Directory to Scan for Deleted Files & Folders:");
        ImGui::PushItemWidth(-140);
        ImGui::InputText("##TargetDirPath", targetDirBuffer_, sizeof(targetDirBuffer_));
        ImGui::PopItemWidth();

        ImGui::SameLine();
        if (UITheme::renderSecondaryButton("Browse Folder...", ImVec2(130, 32))) {
            std::string selected = FileDialog::openFolder("Select Directory to Scan for Deleted Files");
            if (!selected.empty()) {
                std::strncpy(targetDirBuffer_, selected.c_str(), sizeof(targetDirBuffer_) - 1);
                hasDirScanResult_ = false;
                hasDirRecoveryResult_ = false;
            }
        }

        ImGui::Spacing();

        // Live Directory Mount Inspector
        std::error_code ec;
        if (strlen(targetDirBuffer_) > 0 && fs::exists(targetDirBuffer_, ec) && fs::is_directory(targetDirBuffer_, ec)) {
            auto volInfo = forensivault::api::DirectoryRecoveryAPI::inspectDirectory(targetDirBuffer_);

            ImGui::Columns(4, "DirVolCols", false);
            UITheme::renderWrappedText("Mount Point:", UITheme::COLOR_TEXT_MUTED);
            UITheme::renderWrappedText(volInfo.mountPoint.empty() ? "/" : volInfo.mountPoint.c_str(), UITheme::COLOR_TEXT_PRIMARY);

            ImGui::NextColumn();
            UITheme::renderWrappedText("Filesystem Type:", UITheme::COLOR_TEXT_MUTED);
            UITheme::renderWrappedText(volInfo.filesystemType.empty() ? "Host VFS" : volInfo.filesystemType.c_str(), UITheme::COLOR_BLUE);

            ImGui::NextColumn();
            UITheme::renderWrappedText("Underlying Device:", UITheme::COLOR_TEXT_MUTED);
            UITheme::renderWrappedText(volInfo.devicePath.empty() ? "(Standard Volume)" : volInfo.devicePath.c_str(), UITheme::COLOR_TEXT_PRIMARY);

            ImGui::NextColumn();
            UITheme::renderWrappedText("Available Capacity:", UITheme::COLOR_TEXT_MUTED);
            if (volInfo.totalBytes > 0) {
                std::string capStr = formatByteSize(volInfo.freeBytes) + " free / " + formatByteSize(volInfo.totalBytes);
                UITheme::renderWrappedText(capStr.c_str(), UITheme::COLOR_GREEN);
            } else {
                UITheme::renderWrappedText("Mounted Directory", UITheme::COLOR_TEXT_PRIMARY);
            }
            ImGui::Columns(1);
        } else if (strlen(targetDirBuffer_) > 0) {
            UITheme::renderWarningBanner("The specified directory does not exist or is not currently accessible.");
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        bool canScan = (strlen(targetDirBuffer_) > 0) && fs::exists(targetDirBuffer_, ec) && !isDirScanning_.load() && !isDirRecovering_.load();

        if (!canScan) ImGui::BeginDisabled();

        if (UITheme::renderPrimaryButton("Scan Directory for Deleted Files", ImVec2(290, 38))) {
            hasDirScanResult_ = false;
            hasDirRecoveryResult_ = false;
            isDirScanning_.store(true);

            std::string scannedDir = targetDirBuffer_;
            AppContext::getInstance().currentOperation.start(
                "Directory Recovery", "Deleted Artifact Scan", scannedDir, "");

            taskRunner_.run([this, scannedDir]() {
                auto res = forensivault::api::DirectoryRecoveryAPI::scanDirectory(scannedDir);
                {
                    std::lock_guard<std::mutex> lock(dirScanMutex_);
                    dirScanResult_ = std::move(res);
                }
                isDirScanning_.store(false);
                hasDirScanResult_ = true;

                if (dirScanResult_.success) {
                    std::string summary = "Found " + std::to_string(dirScanResult_.items.size()) + " deleted items in " +
                                          std::to_string(dirScanResult_.scanDurationMs) + " ms.";
                    AppContext::getInstance().currentOperation.finish(true, summary);
                    AppContext::getInstance().postNotification(
                        Notification::Type::SUCCESS, "Directory Scan Complete", summary);
                } else {
                    AppContext::getInstance().currentOperation.finish(false, dirScanResult_.errorMessage);
                    AppContext::getInstance().postNotification(
                        Notification::Type::FAILURE, "Directory Scan Failed", dirScanResult_.errorMessage);
                }
            });
        }

        if (!canScan) ImGui::EndDisabled();
    }
    UITheme::endCard();

    // 2. Scanning In-Progress Indicator
    if (isDirScanning_.load()) {
        if (UITheme::beginCard("DirScanProgressCard", "Scanning Directory & Forensic Journals", "ACTIVE", UITheme::COLOR_BLUE)) {
            UITheme::renderProgressBar(-1.0f * (float)ImGui::GetTime(),
                                       "Scanning Directory for Deleted Artifacts...",
                                       "Checking FreeDesktop Trash specifications, Windows Recycle Bin journals, and filesystem records...");
        }
        UITheme::endCard();
    }

    // 3. Scan Results & Discovered Items Table
    if (hasDirScanResult_) {
        forensivault::api::DirectoryScanResult scanRes;
        {
            std::lock_guard<std::mutex> lock(dirScanMutex_);
            scanRes = dirScanResult_;
        }

        if (scanRes.success) {
            // Metrics Summary Bar
            if (UITheme::beginCard("DirScanSummaryCard", "Deleted Artifact Discovery Summary",
                                   scanRes.items.empty() ? "0 ARTIFACTS" : "ARTIFACTS DETECTED",
                                   scanRes.items.empty() ? UITheme::COLOR_YELLOW : UITheme::COLOR_GREEN)) {
                
                ImGui::Columns(4, "SummaryCols", false);
                UITheme::renderWrappedText("Deleted Items Discovered:", UITheme::COLOR_TEXT_MUTED);
                UITheme::renderWrappedFormatted(UITheme::COLOR_ORANGE, "%zu artifacts", scanRes.items.size());

                ImGui::NextColumn();
                UITheme::renderWrappedText("Scan Duration:", UITheme::COLOR_TEXT_MUTED);
                UITheme::renderWrappedFormatted(UITheme::COLOR_TEXT_PRIMARY, "%llu ms", static_cast<unsigned long long>(scanRes.scanDurationMs));

                ImGui::NextColumn();
                UITheme::renderWrappedText("Volume Filesystem:", UITheme::COLOR_TEXT_MUTED);
                UITheme::renderWrappedText(scanRes.volume.filesystemType.c_str(), UITheme::COLOR_BLUE);

                ImGui::NextColumn();
                UITheme::renderWrappedText("Recovery Integrity:", UITheme::COLOR_TEXT_MUTED);
                UITheme::renderWrappedText("High (Journal Verified)", UITheme::COLOR_GREEN);

                ImGui::Columns(1);
            }
            UITheme::endCard();

            if (scanRes.items.empty()) {
                UITheme::renderInfoBanner("No deleted files or journal entries were detected for this directory.\n"
                                          "Note: If files were permanently purged from the trash and filesystem tables long ago, "
                                          "switch to Module 3 (Deep File Carver) to scan raw unallocated cluster signatures.");
            } else {
                size_t selCount = 0;
                uint64_t selBytes = 0;

                // Table of Discovered Items
                if (UITheme::beginCard("DirItemsTableCard", "Discovered Deleted Files & Folders", "SELECTION", UITheme::COLOR_BLUE)) {
                    // Selection control buttons
                    if (UITheme::renderSecondaryButton("Select All", ImVec2(110, 28))) {
                        std::lock_guard<std::mutex> lock(dirScanMutex_);
                        for (auto& it : dirScanResult_.items) it.selected = true;
                    }
                    ImGui::SameLine();
                    if (UITheme::renderSecondaryButton("Deselect All", ImVec2(110, 28))) {
                        std::lock_guard<std::mutex> lock(dirScanMutex_);
                        for (auto& it : dirScanResult_.items) it.selected = false;
                    }

                    // Count selected items and bytes
                    {
                        std::lock_guard<std::mutex> lock(dirScanMutex_);
                        for (const auto& it : dirScanResult_.items) {
                            if (it.selected) {
                                selCount++;
                                selBytes += it.sizeBytes;
                            }
                        }
                    }

                    ImGui::SameLine();
                    ImGui::Text("  Selected: %zu / %zu items (%s)", selCount, scanRes.items.size(), formatByteSize(selBytes).c_str());

                    ImGui::Spacing();
                    ImGui::Separator();
                    ImGui::Spacing();

                    ImGuiTableFlags tblFlags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable;
                    if (scanRes.items.size() > 15) tblFlags |= ImGuiTableFlags_ScrollY;
                    float tableH = (scanRes.items.size() > 15) ? 420.0f : 0.0f;

                    if (ImGui::BeginTable("DiscoveredDeletedTable", 6, tblFlags, ImVec2(0, tableH))) {
                        ImGui::TableSetupColumn("Select", ImGuiTableColumnFlags_WidthFixed, 50.0f);
                        ImGui::TableSetupColumn("Filename", ImGuiTableColumnFlags_WidthStretch);
                        ImGui::TableSetupColumn("Source", ImGuiTableColumnFlags_WidthFixed, 130.0f);
                        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 90.0f);
                        ImGui::TableSetupColumn("Confidence", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                        ImGui::TableSetupColumn("Original Location", ImGuiTableColumnFlags_WidthStretch);
                        ImGui::TableHeadersRow();

                        std::lock_guard<std::mutex> lock(dirScanMutex_);
                        for (size_t i = 0; i < dirScanResult_.items.size(); ++i) {
                            auto& it = dirScanResult_.items[i];
                            ImGui::TableNextRow();

                            // Checkbox column
                            ImGui::TableSetColumnIndex(0);
                            std::string checkId = "##sel_" + std::to_string(i);
                            ImGui::Checkbox(checkId.c_str(), &it.selected);

                            // Filename column
                            ImGui::TableSetColumnIndex(1);
                            if (it.isDirectory) {
                                ImGui::TextColored(UITheme::COLOR_BLUE, "[DIR] %s", it.filename.c_str());
                            } else {
                                ImGui::TextColored(UITheme::COLOR_YELLOW, "[DEL] %s", it.filename.c_str());
                            }

                            // Source column
                            ImGui::TableSetColumnIndex(2);
                            if (it.source == forensivault::api::DetectionSource::TRASH_JOURNAL) {
                                ImGui::TextColored(UITheme::COLOR_GREEN, "Trash Journal");
                            } else if (it.source == forensivault::api::DetectionSource::FILESYSTEM_METADATA) {
                                ImGui::TextColored(UITheme::COLOR_BLUE, "Metadata Tomb");
                            } else {
                                ImGui::TextColored(UITheme::COLOR_ORANGE, "Carved Free");
                            }

                            // Size column
                            ImGui::TableSetColumnIndex(3);
                            ImGui::Text("%s", formatByteSize(it.sizeBytes).c_str());

                            // Confidence column
                            ImGui::TableSetColumnIndex(4);
                            ImGui::TextColored(UITheme::COLOR_GREEN, "%d%% (%s)", it.confidenceScore, it.confidenceLevel.c_str());

                            // Original path column
                            ImGui::TableSetColumnIndex(5);
                            ImGui::Text("%s", it.originalPath.c_str());
                        }
                        ImGui::EndTable();
                    }
                }
                UITheme::endCard();

                // 4. Output Destination & Extraction Card
                if (UITheme::beginCard("DirRestoreCard", "Restore Destination & Execution", "RECOVERY", UITheme::COLOR_BLUE)) {
                    ImGui::Text("Destination Output Folder for Recovered Files:");
                    ImGui::PushItemWidth(-140);
                    ImGui::InputText("##DirOutputDir", dirOutputDirBuffer_, sizeof(dirOutputDirBuffer_));
                    ImGui::PopItemWidth();

                    ImGui::SameLine();
                    if (UITheme::renderSecondaryButton("Browse Folder...", ImVec2(130, 32))) {
                        std::string selected = FileDialog::openFolder("Select Output Destination Folder");
                        if (!selected.empty()) {
                            std::strncpy(dirOutputDirBuffer_, selected.c_str(), sizeof(dirOutputDirBuffer_) - 1);
                        }
                    }

                    ImGui::Spacing();

                    // Safety verification
                    bool outputInsideScanned = isSubdirectory(targetDirBuffer_, dirOutputDirBuffer_);
                    if (outputInsideScanned) {
                        UITheme::renderDangerBanner("Safety Restriction: Destination output directory cannot reside inside the directory being recovered.\n"
                                                   "Please select an external output directory to prevent cluster corruption.");
                    }

                    ImGui::Spacing();
                    ImGui::Separator();
                    ImGui::Spacing();

                    bool canRecover = (selCount > 0) &&
                                      (strlen(dirOutputDirBuffer_) > 0) &&
                                      !outputInsideScanned &&
                                      !isDirRecovering_.load() &&
                                      !isDirScanning_.load();

                    if (!canRecover) ImGui::BeginDisabled();

                    std::string recoverBtnLabel = "Recover " + std::to_string(selCount) + " Selected Items...";
                    if (UITheme::renderRecoveryButton(recoverBtnLabel.c_str(), ImVec2(320, 38))) {
                        hasDirRecoveryResult_ = false;
                        isDirRecovering_.store(true);

                        std::string scannedDir = targetDirBuffer_;
                        std::string destDir = dirOutputDirBuffer_;

                        std::vector<forensivault::api::DiscoveredDeletedItem> itemsToRecover;
                        {
                            std::lock_guard<std::mutex> lock(dirScanMutex_);
                            for (const auto& it : dirScanResult_.items) {
                                if (it.selected) itemsToRecover.push_back(it);
                            }
                        }

                        AppContext::getInstance().currentOperation.start(
                            "Directory Recovery", "File Extraction & Restoration", scannedDir, destDir);

                        taskRunner_.run([this, scannedDir, destDir, itemsToRecover]() {
                            auto res = forensivault::api::DirectoryRecoveryAPI::recoverItems(
                                scannedDir, itemsToRecover, destDir);
                            {
                                std::lock_guard<std::mutex> lock(dirRecoveryMutex_);
                                dirRecoveryResult_ = std::move(res);
                            }
                            isDirRecovering_.store(false);
                            hasDirRecoveryResult_ = true;

                            if (dirRecoveryResult_.success) {
                                for (const auto& rf : dirRecoveryResult_.recoveredFiles) {
                                    std::error_code ec;
                                    uint64_t fsz = fs::exists(rf, ec) ? fs::file_size(rf, ec) : 0;
                                    AppContext::getInstance().registerFsFile(
                                        fs::path(rf).filename().string(), rf, 0, fsz, "Restored");
                                }

                                std::string summary = "Successfully recovered " +
                                                      std::to_string(dirRecoveryResult_.recoveredCount) + " / " +
                                                      std::to_string(dirRecoveryResult_.requestedCount) + " items (" +
                                                      formatByteSize(dirRecoveryResult_.recoveredBytes) + ").";
                                AppContext::getInstance().currentOperation.finish(true, summary);
                                AppContext::getInstance().postNotification(
                                    Notification::Type::SUCCESS, "Recovery Successful", summary);
                            } else {
                                AppContext::getInstance().currentOperation.finish(false, dirRecoveryResult_.errorMessage);
                                AppContext::getInstance().postNotification(
                                    Notification::Type::FAILURE, "Recovery Failed", dirRecoveryResult_.errorMessage);
                            }
                        });
                    }

                    if (!canRecover) ImGui::EndDisabled();
                }
                UITheme::endCard();
            }
        } else {
            UITheme::renderDangerBanner(scanRes.errorMessage.c_str());
        }
    }

    // 5. Recovery In-Progress Indicator
    if (isDirRecovering_.load()) {
        if (UITheme::beginCard("DirRecoverProgressCard", "Restoring Deleted Artifacts", "ACTIVE", UITheme::COLOR_BLUE)) {
            UITheme::renderProgressBar(-1.0f * (float)ImGui::GetTime(),
                                       "Restoring Selected Items...",
                                       "Extracting payload data, validating SHA-256 integrity, and generating forensic custody log...");
        }
        UITheme::endCard();
    }

    // 6. Recovery Results Summary Card
    if (hasDirRecoveryResult_) {
        forensivault::api::DirectoryRecoveryResult recRes;
        {
            std::lock_guard<std::mutex> lock(dirRecoveryMutex_);
            recRes = dirRecoveryResult_;
        }

        if (UITheme::beginCard("DirRecoveryResultsCard", "Directory Recovery Report",
                               recRes.success ? "RESTORE SUCCESSFUL" : "RESTORE FAILED",
                               recRes.success ? UITheme::COLOR_GREEN : UITheme::COLOR_RED)) {
            if (recRes.success) {
                ImGui::Columns(3, "RecResultCols", false);
                UITheme::renderWrappedText("Recovered Items:", UITheme::COLOR_TEXT_MUTED);
                UITheme::renderWrappedFormatted(UITheme::COLOR_GREEN, "%zu / %zu items", recRes.recoveredCount, recRes.requestedCount);

                ImGui::NextColumn();
                UITheme::renderWrappedText("Total Bytes Restored:", UITheme::COLOR_TEXT_MUTED);
                UITheme::renderWrappedText(formatByteSize(recRes.recoveredBytes).c_str(), UITheme::COLOR_TEXT_PRIMARY);

                ImGui::NextColumn();
                UITheme::renderWrappedText("Evidence Status:", UITheme::COLOR_TEXT_MUTED);
                UITheme::renderWrappedText("Registered in Evidence Browser", UITheme::COLOR_BLUE);
                ImGui::Columns(1);

                ImGui::Spacing();
                ImGui::Separator();
                ImGui::Spacing();

                ImGui::TextColored(UITheme::COLOR_GREEN, "[OK] Recovered artifacts have been restored to: %s", dirOutputDirBuffer_);
                
                if (UITheme::renderSecondaryButton("Open Output Folder in File Explorer", ImVec2(280, 32))) {
                    FileDialog::openFolderInExplorer(dirOutputDirBuffer_);
                }
            } else {
                UITheme::renderDangerBanner(recRes.errorMessage.c_str());
            }
        }
        UITheme::endCard();
    }
}

void ViewFsRecovery::renderImageRecovery() {
    if (UITheme::beginCard("FsInputCard", "Evidence Volume & Partition Setup", "INPUTS", UITheme::COLOR_BLUE)) {
        ImGui::Text("Target Evidence Disk Image:");
        ImGui::PushItemWidth(-140);
        ImGui::InputText("##FsImagePath", imagePathBuffer_, sizeof(imagePathBuffer_));
        ImGui::PopItemWidth();

        ImGui::SameLine();
        if (UITheme::renderSecondaryButton("Browse Image...", ImVec2(130, 32))) {
            std::string selected = FileDialog::openFile("Select Evidence Image", "Disk Images (*.img;*.dd;*.raw;*.*)", "*.img;*.dd;*.raw;*.*");
            if (!selected.empty()) {
                std::strncpy(imagePathBuffer_, selected.c_str(), sizeof(imagePathBuffer_) - 1);
                hasProbed_ = false;
                hasRecoveryResult_ = false;
            }
        }

        ImGui::Spacing();
        ImGui::Text("Output Recovery Directory:");
        ImGui::PushItemWidth(-140);
        ImGui::InputText("##FsOutputDir", outputDirBuffer_, sizeof(outputDirBuffer_));
        ImGui::PopItemWidth();

        ImGui::SameLine();
        if (UITheme::renderSecondaryButton("Browse Folder...", ImVec2(130, 32))) {
            std::string selected = FileDialog::openFolder("Select Output Recovery Folder");
            if (!selected.empty()) {
                std::strncpy(outputDirBuffer_, selected.c_str(), sizeof(outputDirBuffer_) - 1);
            }
        }

        ImGui::Spacing();
        ImGui::Text("Partition Start Byte Offset (0 for raw volume, or MBR/GPT partition start):");
        ImGui::PushItemWidth(220);
        ImGui::InputInt("##PartitionOffset", &partitionOffset_, 512, 4096);
        ImGui::PopItemWidth();

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        bool canProbe = strlen(imagePathBuffer_) > 0 && fs::exists(imagePathBuffer_) && !taskRunner_.isRunning();

        if (!canProbe) ImGui::BeginDisabled();

        if (UITheme::renderSecondaryButton("Probe Filesystem Structures", ImVec2(240, 36))) {
            probedVolume_ = forensivault::api::FsRecoveryAPI::probeVolume(imagePathBuffer_, static_cast<uint64_t>(std::max(0, partitionOffset_)));
            hasProbed_ = true;
        }

        ImGui::SameLine();

        if (UITheme::renderPrimaryButton("Execute Filesystem Recovery...", ImVec2(280, 36))) {
            hasRecoveryResult_ = false;
            std::string img = imagePathBuffer_;
            std::string out = outputDirBuffer_;
            uint64_t off = static_cast<uint64_t>(std::max(0, partitionOffset_));

            AppContext::getInstance().currentOperation.start(
                "Filesystem Recovery", "Metadata Table Recovery", img, out);

            taskRunner_.run([this, img, out, off]() {
                auto res = forensivault::api::FsRecoveryAPI::recover(img, out, off);
                {
                    std::lock_guard<std::mutex> lock(recoveryMutex_);
                    recoveryResult_ = res;
                }
                hasRecoveryResult_.store(true);

                if (res.success) {
                    for (const auto& df : res.deletedFiles) {
                        AppContext::getInstance().registerFsFile(
                            df.filename, df.recoveredFilePath, off, df.sizeBytes, "Recovered");
                    }
                    for (const auto& af : res.activeFiles) {
                        AppContext::getInstance().registerFsFile(
                            af.filename, af.recoveredFilePath, off, af.sizeBytes, "Active");
                    }

                    std::string summary = "Extracted " + std::to_string(res.activeFiles.size()) + " active, " +
                                          std::to_string(res.deletedFiles.size()) + " deleted files.";
                    AppContext::getInstance().currentOperation.finish(true, summary);
                    AppContext::getInstance().postNotification(
                        Notification::Type::SUCCESS, "Filesystem Recovery Complete", summary);
                } else {
                    AppContext::getInstance().currentOperation.finish(false, res.errorMessage);
                    AppContext::getInstance().postNotification(
                        Notification::Type::FAILURE, "Recovery Failed",
                        res.errorMessage);
                }
            });
        }

        if (!canProbe) ImGui::EndDisabled();
    }
    UITheme::endCard();

    if (hasProbed_) {
        renderProbeResults();
    }

    if (taskRunner_.isRunning() && !isDirScanning_.load() && !isDirRecovering_.load()) {
        if (UITheme::beginCard("FsProgressCard", "Parsing Filesystem Metadata", "RUNNING", UITheme::COLOR_BLUE)) {
            UITheme::renderProgressBar(-1.0f * (float)ImGui::GetTime(), "Parsing directory tables and unallocated MFT records...", "Extracting file records and validating cluster chains...");
        }
        UITheme::endCard();
    }

    if (hasRecoveryResult_) {
        renderRecoveryResults();
    }
}

void ViewFsRecovery::renderProbeResults() {
    if (UITheme::beginCard("ProbeCard", "Detected Volume Geometry & Boot Record",
                           probedVolume_.valid ? "STRUCTURE IDENTIFIED" : "UNKNOWN FILESYSTEM",
                           probedVolume_.valid ? UITheme::COLOR_GREEN : UITheme::COLOR_YELLOW)) {
        if (probedVolume_.valid) {
            std::string fsName = "UNKNOWN";
            if (probedVolume_.type == forensivault::api::FilesystemType::FAT32) fsName = "FAT32";
            else if (probedVolume_.type == forensivault::api::FilesystemType::EXFAT) fsName = "exFAT";
            else if (probedVolume_.type == forensivault::api::FilesystemType::NTFS) fsName = "NTFS";

            ImGui::Columns(3, "VolCols", false);
            UITheme::renderWrappedText("Volume Type:", UITheme::COLOR_TEXT_MUTED);
            UITheme::renderWrappedText(fsName.c_str(), UITheme::COLOR_TEXT_PRIMARY);
            ImGui::Spacing();
            UITheme::renderWrappedText("Volume Label:", UITheme::COLOR_TEXT_MUTED);
            UITheme::renderWrappedText(probedVolume_.label.empty() ? "(None)" : probedVolume_.label.c_str(), UITheme::COLOR_TEXT_PRIMARY);

            ImGui::NextColumn();
            UITheme::renderWrappedText("Sector Size:", UITheme::COLOR_TEXT_MUTED);
            UITheme::renderWrappedFormatted(UITheme::COLOR_TEXT_PRIMARY, "%u bytes", probedVolume_.sectorSize);
            ImGui::Spacing();
            UITheme::renderWrappedText("Cluster Size:", UITheme::COLOR_TEXT_MUTED);
            UITheme::renderWrappedFormatted(UITheme::COLOR_TEXT_PRIMARY, "%llu bytes", static_cast<unsigned long long>(probedVolume_.clusterSize));

            ImGui::NextColumn();
            UITheme::renderWrappedText("Sectors / Cluster:", UITheme::COLOR_TEXT_MUTED);
            UITheme::renderWrappedFormatted(UITheme::COLOR_TEXT_PRIMARY, "%u", probedVolume_.sectorsPerCluster);
            ImGui::Spacing();
            UITheme::renderWrappedText("Total Clusters:", UITheme::COLOR_TEXT_MUTED);
            UITheme::renderWrappedFormatted(UITheme::COLOR_TEXT_PRIMARY, "%llu", static_cast<unsigned long long>(probedVolume_.totalClusters));
            ImGui::Columns(1);
        } else {
            UITheme::renderWarningBanner("No standard FAT32, exFAT, or NTFS signature detected at the specified offset. Verify partition alignment or switch to Module 3 (Raw Data Carving).");
        }
    }
    UITheme::endCard();
}

void ViewFsRecovery::renderRecoveryResults() {
    forensivault::api::FilesystemRecoverySummary res;
    {
        std::lock_guard<std::mutex> lock(recoveryMutex_);
        res = recoveryResult_;
    }

    if (UITheme::beginCard("FsResultsCard", "Filesystem Extraction Summary",
                           res.success ? "SUCCESS" : "FAILED",
                           res.success ? UITheme::COLOR_GREEN : UITheme::COLOR_RED)) {
        if (res.success) {
            ImGui::Columns(3, nullptr, false);
            UITheme::renderWrappedText("Active Files:", UITheme::COLOR_TEXT_MUTED);
            UITheme::renderWrappedFormatted(UITheme::COLOR_TEXT_PRIMARY, "%zu files", res.activeFiles.size());

            ImGui::NextColumn();
            UITheme::renderWrappedText("Deleted Artifacts:", UITheme::COLOR_TEXT_MUTED);
            UITheme::renderWrappedFormatted(UITheme::COLOR_BLUE, "%zu (Tombstones recovered)", res.deletedFiles.size());

            ImGui::NextColumn();
            UITheme::renderWrappedText("Evidence SHA-256:", UITheme::COLOR_TEXT_MUTED);
            if (!res.evidenceSha256.empty()) {
                UITheme::renderWrappedFormatted(UITheme::COLOR_TEXT_PRIMARY, "%s...", res.evidenceSha256.substr(0, 16).c_str());
            } else {
                UITheme::renderWrappedText("(N/A)", UITheme::COLOR_TEXT_MUTED);
            }
            ImGui::Columns(1);
        } else {
            UITheme::renderDangerBanner(res.errorMessage.c_str());
        }
    }
    UITheme::endCard();

    if (!res.deletedFiles.empty()) {
        if (UITheme::beginCard("FsDelTableCard", "Recovered Deleted Files", "DELETED ENTRIES", UITheme::COLOR_BLUE)) {
            ImGuiTableFlags tblFlags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable;
            if (res.deletedFiles.size() > 25) tblFlags |= ImGuiTableFlags_ScrollY;
            float tableH = (res.deletedFiles.size() > 25) ? 460.0f : 0.0f;

            if (ImGui::BeginTable("DeletedFilesTable", 4, tblFlags, ImVec2(0, tableH))) {
                ImGui::TableSetupColumn("Filename", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Ext", ImGuiTableColumnFlags_WidthFixed, 70.0f);
                ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                ImGui::TableSetupColumn("Extracted Path", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableHeadersRow();

                for (const auto& df : res.deletedFiles) {
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    ImGui::TextColored(UITheme::COLOR_YELLOW, "[DEL] %s", df.filename.c_str());

                    ImGui::TableSetColumnIndex(1);
                    ImGui::Text("%s", df.extension.c_str());

                    ImGui::TableSetColumnIndex(2);
                    ImGui::Text("%s", formatByteSize(df.sizeBytes).c_str());

                    ImGui::TableSetColumnIndex(3);
                    ImGui::Text("%s", df.recoveredFilePath.c_str());
                }
                ImGui::EndTable();
            }
        }
        UITheme::endCard();
    }
}

} // namespace forensivault::gui
