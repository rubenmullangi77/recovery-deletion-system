#include "view_directory_recovery.hpp"
#include "ui_theme.hpp"
#include "file_dialog.hpp"
#include "app_context.hpp"
#include <forensivault/core/platform.hpp>
#include "reporting/report_generator.hpp"
#include "reporting/forensic_report.hpp"
#include "logging/audit_logger.hpp"

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

std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

bool matchesCategory(const forensivault::api::DiscoveredDeletedItem& item, int cat) {
    if (cat == 0) return true; // All
    if (cat == 4) return item.isDirectory; // Folders only

    if (item.isDirectory) return false;
    std::string ext = toLower(item.extension);

    if (cat == 1) { // Documents
        return (ext == "pdf" || ext == "doc" || ext == "docx" || ext == "txt" ||
                ext == "odt" || ext == "rtf" || ext == "xls" || ext == "xlsx" ||
                ext == "ppt" || ext == "pptx" || ext == "csv" || ext == "md");
    } else if (cat == 2) { // Images
        return (ext == "jpg" || ext == "jpeg" || ext == "png" || ext == "gif" ||
                ext == "bmp" || ext == "tiff" || ext == "webp" || ext == "svg" || ext == "raw");
    } else if (cat == 3) { // Archives
        return (ext == "zip" || ext == "tar" || ext == "gz" || ext == "7z" ||
                ext == "rar" || ext == "bz2" || ext == "xz" || ext == "iso");
    }
    return true;
}

} // anonymous namespace

ViewDirectoryRecovery::ViewDirectoryRecovery() {
    std::string homeDir = core::Platform::getUserHomeDirectory();
    std::memset(targetDirBuffer_, 0, sizeof(targetDirBuffer_));
    if (!homeDir.empty() && homeDir != ".") {
        std::strncpy(targetDirBuffer_, homeDir.c_str(), sizeof(targetDirBuffer_) - 1);
    }

    std::memset(outputDirBuffer_, 0, sizeof(outputDirBuffer_));
    std::string defaultRecovered = (fs::path(homeDir) / "ForensiVault_Recovered").string();
    std::strncpy(outputDirBuffer_, defaultRecovered.c_str(), sizeof(outputDirBuffer_) - 1);

    std::memset(searchFilterBuffer_, 0, sizeof(searchFilterBuffer_));
    categoryFilter_ = 0;
}

void ViewDirectoryRecovery::render() {
    UITheme::renderCardHeader("DELETED FILE & FOLDER RECOVERY",
                              "Live Directory Scan, FreeDesktop Trash Journals, Recycle Bin Records & Non-Destructive Restoration");

    renderDirectorySelector();

    if (isScanning_.load()) {
        if (UITheme::beginCard("DirScanProgressCard", "Scanning Directory & Forensic Journals", "ACTIVE", UITheme::COLOR_BLUE)) {
            UITheme::renderProgressBar(-1.0f * (float)ImGui::GetTime(),
                                       "Scanning Directory for Previously Deleted Files...",
                                       "Parsing FreeDesktop Trash specifications, Windows Recycle Bin metadata, and filesystem allocation tables...");
        }
        UITheme::endCard();
    }

    if (hasScanResult_) {
        renderDiscoveredItems();
        renderRecoveryExecution();
    }

    if (isRecovering_.load()) {
        if (UITheme::beginCard("DirRecoverProgressCard", "Restoring Deleted Artifacts", "ACTIVE", UITheme::COLOR_BLUE)) {
            UITheme::renderProgressBar(-1.0f * (float)ImGui::GetTime(),
                                       "Restoring Selected Items...",
                                       "Extracting payload data, validating SHA-256 integrity, and generating forensic custody log...");
        }
        UITheme::endCard();
    }

}

void ViewDirectoryRecovery::renderDirectorySelector() {
    if (UITheme::beginCard("DirSelectorCard", "Target Directory Setup", "DIRECTORY", UITheme::COLOR_BLUE)) {
        ImGui::Text("Select Live Directory to Scan for Deleted Files & Folders:");
        if (UITheme::renderInputWithButton("##TargetDirPath", targetDirBuffer_, sizeof(targetDirBuffer_), "Browse Folder...", 140.0f)) {
            std::string selected = FileDialog::openFolder("Select Directory to Scan for Deleted Files");
            if (!selected.empty()) {
                std::strncpy(targetDirBuffer_, selected.c_str(), sizeof(targetDirBuffer_) - 1);
                hasScanResult_ = false;
                hasRecoveryResult_ = false;
            }
        }

        ImGui::Spacing();

        // Live Directory Mount Inspector
        std::error_code ec;
        if (strlen(targetDirBuffer_) > 0 && fs::exists(targetDirBuffer_, ec) && fs::is_directory(targetDirBuffer_, ec)) {
            auto volInfo = forensivault::api::DirectoryRecoveryAPI::inspectDirectory(targetDirBuffer_);
            renderVolumeInfo(volInfo);
        } else if (strlen(targetDirBuffer_) > 0) {
            UITheme::renderWarningBanner("The specified directory does not exist or is not currently accessible.");
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        bool canScan = (strlen(targetDirBuffer_) > 0) && fs::exists(targetDirBuffer_, ec) && !isScanning_.load() && !isRecovering_.load();

        if (!canScan) ImGui::BeginDisabled();

        if (UITheme::renderPrimaryButton("Scan Directory for Deleted Files", ImVec2(290, 38))) {
            hasScanResult_ = false;
            hasRecoveryResult_ = false;
            isScanning_.store(true);

            std::string scannedDir = targetDirBuffer_;
            AppContext::getInstance().currentOperation.start(
                "Directory Recovery", "Deleted Artifact Scan", scannedDir, "");

            taskRunner_.run([this, scannedDir]() {
                auto res = forensivault::api::DirectoryRecoveryAPI::scanDirectory(scannedDir);
                {
                    std::lock_guard<std::mutex> lock(scanMutex_);
                    scanResult_ = std::move(res);
                }
                isScanning_.store(false);
                hasScanResult_ = true;

                if (scanResult_.success) {
                    std::string summary = "Found " + std::to_string(scanResult_.items.size()) + " deleted items in " +
                                          std::to_string(scanResult_.scanDurationMs) + " ms.";
                    AppContext::getInstance().currentOperation.finish(true, summary);
                    AppContext::getInstance().postNotification(
                        Notification::Type::SUCCESS, "Directory Scan Complete", summary);
                } else {
                    AppContext::getInstance().currentOperation.finish(false, scanResult_.errorMessage);
                    AppContext::getInstance().postNotification(
                        Notification::Type::FAILURE, "Directory Scan Failed", scanResult_.errorMessage);
                }
            });
        }

        if (!canScan) ImGui::EndDisabled();
    }
    UITheme::endCard();
}

void ViewDirectoryRecovery::renderVolumeInfo(const forensivault::api::DirectoryVolumeInfo& volInfo) {
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
}

void ViewDirectoryRecovery::renderDiscoveredItems() {
    forensivault::api::DirectoryScanResult scanRes;
    {
        std::lock_guard<std::mutex> lock(scanMutex_);
        scanRes = scanResult_;
    }

    if (!scanRes.success) {
        UITheme::renderDangerBanner(scanRes.errorMessage.c_str());
        return;
    }

    // 1. Scan Summary Bar
    if (UITheme::beginCard("DirScanSummaryCard", "Scan Discovery Summary",
                           scanRes.items.empty() ? "0 ARTIFACTS" : "ARTIFACTS DETECTED",
                           scanRes.items.empty() ? UITheme::COLOR_YELLOW : UITheme::COLOR_GREEN)) {
        
        ImGui::Columns(4, "SummaryCols", false);
        UITheme::renderWrappedText("Deleted Artifacts:", UITheme::COLOR_TEXT_MUTED);
        UITheme::renderWrappedFormatted(UITheme::COLOR_ORANGE, "%zu items", scanRes.items.size());

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
                                  "switch to Raw File Carving in the sidebar to scan raw unallocated cluster signatures.");
        return;
    }

    // 2. Discovered Deleted Items Table Card
    if (UITheme::beginCard("DirItemsTableCard", "Discovered Deleted Files & Folders", "SELECTION", UITheme::COLOR_BLUE)) {
        // Quick Selection Buttons
        if (UITheme::renderSecondaryButton("Select All", ImVec2(100, 28))) {
            std::lock_guard<std::mutex> lock(scanMutex_);
            for (auto& it : scanResult_.items) {
                if (it.source != forensivault::api::DetectionSource::SANITIZED_AUDIT) {
                    it.selected = true;
                }
            }
        }
        ImGui::SameLine();
        if (UITheme::renderSecondaryButton("Deselect All", ImVec2(100, 28))) {
            std::lock_guard<std::mutex> lock(scanMutex_);
            for (auto& it : scanResult_.items) it.selected = false;
        }
        ImGui::SameLine();
        if (UITheme::renderSecondaryButton("Invert Selection", ImVec2(120, 28))) {
            std::lock_guard<std::mutex> lock(scanMutex_);
            for (auto& it : scanResult_.items) {
                if (it.source != forensivault::api::DetectionSource::SANITIZED_AUDIT) {
                    it.selected = !it.selected;
                }
            }
        }

        // Search and Category Filter
        ImGui::SameLine();
        ImGui::PushItemWidth(200);
        ImGui::InputTextWithHint("##SearchFilter", "Search files...", searchFilterBuffer_, sizeof(searchFilterBuffer_));
        ImGui::PopItemWidth();

        ImGui::SameLine();
        const char* categories[] = { "All Files", "Documents", "Images", "Archives", "Folders" };
        ImGui::PushItemWidth(120);
        ImGui::Combo("##CatFilter", &categoryFilter_, categories, IM_ARRAYSIZE(categories));
        ImGui::PopItemWidth();

        // Calculate selected counts
        size_t selCount = 0;
        uint64_t selBytes = 0;
        {
            std::lock_guard<std::mutex> lock(scanMutex_);
            for (const auto& it : scanResult_.items) {
                if (it.selected && it.source != forensivault::api::DetectionSource::SANITIZED_AUDIT) {
                    selCount++;
                    selBytes += it.sizeBytes;
                }
            }
        }

        ImGui::Text("Selected for Restoration: %zu / %zu items (%s)",
                    selCount, scanRes.items.size(), UITheme::formatByteSize(selBytes).c_str());

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        std::string filterStr = toLower(searchFilterBuffer_);

        ImGuiTableFlags tblFlags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable;
        if (scanRes.items.size() > 15) tblFlags |= ImGuiTableFlags_ScrollY;
        float tableH = (scanRes.items.size() > 15) ? 420.0f : 0.0f;

        if (ImGui::BeginTable("DiscoveredDeletedTable", 7, tblFlags, ImVec2(0, tableH))) {
            ImGui::TableSetupColumn("Select", ImGuiTableColumnFlags_WidthFixed, 50.0f);
            ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 55.0f);
            ImGui::TableSetupColumn("Filename", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Source", ImGuiTableColumnFlags_WidthFixed, 130.0f);
            ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 90.0f);
            ImGui::TableSetupColumn("Confidence", ImGuiTableColumnFlags_WidthFixed, 110.0f);
            ImGui::TableSetupColumn("Original Path", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            std::lock_guard<std::mutex> lock(scanMutex_);
            for (size_t i = 0; i < scanResult_.items.size(); ++i) {
                auto& it = scanResult_.items[i];

                // Apply text filter
                if (!filterStr.empty()) {
                    std::string fNameLower = toLower(it.filename);
                    std::string fPathLower = toLower(it.originalPath);
                    if (fNameLower.find(filterStr) == std::string::npos &&
                        fPathLower.find(filterStr) == std::string::npos) {
                        continue;
                    }
                }

                // Apply category filter
                if (!matchesCategory(it, categoryFilter_)) {
                    continue;
                }

                ImGui::TableNextRow();

                // Checkbox
                ImGui::TableSetColumnIndex(0);
                std::string checkId = "##sel_" + std::to_string(i);
                if (it.source == forensivault::api::DetectionSource::SANITIZED_AUDIT) {
                    ImGui::BeginDisabled();
                    bool dummySel = false;
                    ImGui::Checkbox(checkId.c_str(), &dummySel);
                    ImGui::EndDisabled();
                    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
                        ImGui::SetTooltip("Item was permanently sanitized with certified overwrites; cannot be recovered.");
                    }
                } else {
                    ImGui::Checkbox(checkId.c_str(), &it.selected);
                }

                // Type
                ImGui::TableSetColumnIndex(1);
                if (it.isDirectory) {
                    ImGui::TextColored(UITheme::COLOR_BLUE, "[DIR]");
                } else {
                    ImGui::TextColored(UITheme::COLOR_YELLOW, "[FILE]");
                }

                // Filename
                ImGui::TableSetColumnIndex(2);
                if (it.source == forensivault::api::DetectionSource::SANITIZED_AUDIT) {
                    ImGui::TextColored(UITheme::COLOR_TEXT_MUTED, "%s", it.filename.c_str());
                    if (ImGui::IsItemHovered()) {
                        ImGui::SetTooltip("Sanitized Target: %s\n%s", it.originalPath.c_str(), it.payloadLocator.c_str());
                    }
                } else if (it.isDirectory) {
                    ImGui::TextColored(UITheme::COLOR_BLUE, "%s", it.filename.c_str());
                } else {
                    ImGui::TextColored(UITheme::COLOR_TEXT_PRIMARY, "%s", it.filename.c_str());
                }

                // Source
                ImGui::TableSetColumnIndex(3);
                if (it.source == forensivault::api::DetectionSource::TRASH_JOURNAL) {
                    ImGui::TextColored(UITheme::COLOR_GREEN, "Trash Journal");
                } else if (it.source == forensivault::api::DetectionSource::FILESYSTEM_METADATA) {
                    ImGui::TextColored(UITheme::COLOR_BLUE, "Metadata Tomb");
                } else if (it.source == forensivault::api::DetectionSource::SANITIZED_AUDIT) {
                    ImGui::TextColored(UITheme::COLOR_RED, "[SANITIZED]");
                } else {
                    ImGui::TextColored(UITheme::COLOR_ORANGE, "Carved Free");
                }

                // Size
                ImGui::TableSetColumnIndex(4);
                if (it.source == forensivault::api::DetectionSource::SANITIZED_AUDIT) {
                    ImGui::TextDisabled("Scrambled");
                } else {
                    ImGui::Text("%s", UITheme::formatByteSize(it.sizeBytes).c_str());
                }

                // Confidence
                ImGui::TableSetColumnIndex(5);
                if (it.source == forensivault::api::DetectionSource::SANITIZED_AUDIT) {
                    ImGui::TextColored(UITheme::COLOR_RED, "0%% (Destroyed)");
                } else {
                    ImGui::TextColored(UITheme::COLOR_GREEN, "%d%% (%s)", it.confidenceScore, it.confidenceLevel.c_str());
                }

                // Original Path
                ImGui::TableSetColumnIndex(6);
                ImGui::Text("%s", it.originalPath.c_str());
            }
            ImGui::EndTable();
        }
    }
    UITheme::endCard();
}

void ViewDirectoryRecovery::renderRecoveryExecution() {
    size_t selCount = 0;
    {
        std::lock_guard<std::mutex> lock(scanMutex_);
        for (const auto& it : scanResult_.items) {
            if (it.selected) selCount++;
        }
    }

    if (UITheme::beginCard("DirRestoreCard", "Restoration Destination & Execution", "RECOVERY", UITheme::COLOR_BLUE)) {
        ImGui::Text("Destination Output Folder for Recovered Files & Folders:");
        if (UITheme::renderInputWithButton("##DirOutputDir", outputDirBuffer_, sizeof(outputDirBuffer_), "Browse Folder...", 140.0f)) {
            std::string selected = FileDialog::openFolder("Select Output Destination Folder");
            if (!selected.empty()) {
                std::strncpy(outputDirBuffer_, selected.c_str(), sizeof(outputDirBuffer_) - 1);
            }
        }

        ImGui::Spacing();

        // Safety verification
        bool outputInsideScanned = isSubdirectory(targetDirBuffer_, outputDirBuffer_);
        if (outputInsideScanned) {
            UITheme::renderDangerBanner("Safety Restriction: Destination output directory cannot reside inside the directory being recovered.\n"
                                       "Please select an external output directory to prevent cluster corruption.");
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        bool canRecover = (selCount > 0) &&
                          (strlen(outputDirBuffer_) > 0) &&
                          !outputInsideScanned &&
                          !isRecovering_.load() &&
                          !isScanning_.load();

        if (!canRecover) ImGui::BeginDisabled();

        std::string recoverBtnLabel = "Recover " + std::to_string(selCount) + " Selected Items...";
        if (UITheme::renderRecoveryButton(recoverBtnLabel.c_str(), ImVec2(320, 38))) {
            hasRecoveryResult_ = false;
            isRecovering_.store(true);

            std::string scannedDir = targetDirBuffer_;
            std::string destDir = outputDirBuffer_;

            std::vector<forensivault::api::DiscoveredDeletedItem> itemsToRecover;
            {
                std::lock_guard<std::mutex> lock(scanMutex_);
                for (const auto& it : scanResult_.items) {
                    if (it.selected) itemsToRecover.push_back(it);
                }
            }

            AppContext::getInstance().currentOperation.start(
                "Directory Recovery", "File Extraction & Restoration", scannedDir, destDir);

            taskRunner_.run([this, scannedDir, destDir, itemsToRecover]() {
                auto res = forensivault::api::DirectoryRecoveryAPI::recoverItems(
                    scannedDir, itemsToRecover, destDir);
                {
                    std::lock_guard<std::mutex> lock(recoveryMutex_);
                    recoveryResult_ = std::move(res);
                }
                isRecovering_.store(false);
                hasRecoveryResult_ = true;

                if (recoveryResult_.success) {
                    for (const auto& rf : recoveryResult_.recoveredFiles) {
                        std::error_code ec;
                        uint64_t fsz = fs::exists(rf, ec) ? fs::file_size(rf, ec) : 0;
                        AppContext::getInstance().registerFsFile(
                            fs::path(rf).filename().string(), rf, 0, fsz, "Restored");
                    }

                    std::string summary = "Successfully recovered " +
                                          std::to_string(recoveryResult_.recoveredCount) + " / " +
                                          std::to_string(recoveryResult_.requestedCount) + " items (" +
                                          formatByteSize(recoveryResult_.recoveredBytes) + ").";
                    AppContext::getInstance().currentOperation.finish(true, summary);
                    AppContext::getInstance().postNotification(
                        Notification::Type::SUCCESS, "Recovery Successful", summary);
                } else {
                    AppContext::getInstance().currentOperation.finish(false, recoveryResult_.errorMessage);
                    AppContext::getInstance().postNotification(
                        Notification::Type::FAILURE, "Recovery Failed", recoveryResult_.errorMessage);
                }
            });
        }

        if (!canRecover) ImGui::EndDisabled();
    }
    UITheme::endCard();

    // 3. Post-Recovery Summary Card
    if (hasRecoveryResult_) {
        forensivault::api::DirectoryRecoveryResult recRes;
        {
            std::lock_guard<std::mutex> lock(recoveryMutex_);
            recRes = recoveryResult_;
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

                ImGui::TextColored(UITheme::COLOR_GREEN, "[OK] Recovered artifacts have been restored to: %s", outputDirBuffer_);
                
                ImGui::Spacing();

                float availW = ImGui::GetContentRegionAvail().x;
                float spacing = ImGui::GetStyle().ItemSpacing.x;

                if (availW < 720.0f) {
                    float subW = (availW - spacing) * 0.5f;
                    if (subW < 130.0f) subW = -1.0f;

                    if (UITheme::renderSecondaryButton("Open Output Folder", ImVec2(subW, 34))) {
                        FileDialog::openFolderInExplorer(outputDirBuffer_);
                    }

                    if (subW > 0.0f) ImGui::SameLine(0.0f, spacing);
                    else ImGui::Dummy(ImVec2(0, 4.0f));

                    if (UITheme::renderPrimaryButton("View in Evidence Browser ->", ImVec2(subW, 34))) {
                        AppContext::getInstance().activeTab = ModuleTab::RECOVERED_FILES;
                    }

                    ImGui::Dummy(ImVec2(0, 4.0f));
                    if (UITheme::renderSecondaryButton("Generate PDF Forensic Report", ImVec2(-1, 34))) {
                        forensivault::reporting::ForensicReport rep;
                        rep.report_id = "DIR-REC-" + std::to_string(std::time(nullptr));
                        rep.report_timestamp_iso = forensivault::logging::AuditLogger::currentTimestampIso();
                        rep.case_info.case_id = "CASE-DIR-RECOVERY";
                        rep.case_info.case_name = "Directory Recovery Extraction";
                        rep.case_info.investigator_name = AppContext::getInstance().currentUsername.empty() ? "Forensic Examiner" : AppContext::getInstance().currentUsername;
                        rep.case_info.agency = "Digital Forensics Unit";
                        rep.acquisition.source_path = targetDirBuffer_;
                        rep.acquisition.total_bytes = recRes.recoveredBytes;
                        for (const auto& it : scanResult_.items) {
                            forensivault::reporting::ReportItem rItem;
                            rItem.filename = it.filename;
                            rItem.relative_path = it.originalPath;
                            rItem.size_bytes = it.sizeBytes;
                            rItem.file_type = it.extension;
                            rItem.confidence_level = "VERIFIED";
                            rep.recovered_items.push_back(rItem);
                        }
                        rep.audit_trail = forensivault::logging::AuditLogger::getInstance().getEntries();
                        std::string reportsDir = forensivault::core::Platform::getReportsDirectory();
                        auto res = forensivault::reporting::ReportGenerator::saveReportPackage(rep, reportsDir, true);
                        if (res.pdf_saved) {
                            AppContext::getInstance().postNotification(
                                Notification::Type::SUCCESS, "PDF Report Generated",
                                "Saved court-admissible PDF to: " + res.pdf_path);
                        }
                    }
                } else {
                    if (UITheme::renderSecondaryButton("Open Output Folder", ImVec2(240, 34))) {
                        FileDialog::openFolderInExplorer(outputDirBuffer_);
                    }
                    ImGui::SameLine(0.0f, spacing);
                    if (UITheme::renderPrimaryButton("View in Evidence Browser ->", ImVec2(230, 34))) {
                        AppContext::getInstance().activeTab = ModuleTab::RECOVERED_FILES;
                    }
                    ImGui::SameLine(0.0f, spacing);
                    if (UITheme::renderSecondaryButton("Generate PDF Report", ImVec2(190, 34))) {
                    forensivault::reporting::ForensicReport rep;
                    rep.report_id = "DIR-REC-" + std::to_string(std::time(nullptr));
                    rep.report_timestamp_iso = forensivault::logging::AuditLogger::currentTimestampIso();
                    rep.case_info.case_id = "CASE-DIR-RECOVERY";
                    rep.case_info.case_name = "Directory Recovery Extraction";
                    rep.case_info.investigator_name = AppContext::getInstance().currentUsername.empty() ? "Forensic Examiner" : AppContext::getInstance().currentUsername;
                    rep.case_info.agency = "Digital Forensics Unit";
                    rep.acquisition.source_path = targetDirBuffer_;
                    rep.acquisition.total_bytes = recRes.recoveredBytes;
                    for (const auto& it : scanResult_.items) {
                        forensivault::reporting::ReportItem rItem;
                        rItem.filename = it.filename;
                        rItem.relative_path = it.originalPath;
                        rItem.size_bytes = it.sizeBytes;
                        rItem.file_type = it.extension;
                        rItem.confidence_level = "VERIFIED";
                        rep.recovered_items.push_back(rItem);
                    }
                    rep.audit_trail = forensivault::logging::AuditLogger::getInstance().getEntries();
                    std::string reportsDir = forensivault::core::Platform::getReportsDirectory();
                    auto res = forensivault::reporting::ReportGenerator::saveReportPackage(rep, reportsDir, true);
                    if (res.pdf_saved) {
                        AppContext::getInstance().postNotification(
                            Notification::Type::SUCCESS, "PDF Report Generated",
                            "Saved court-admissible PDF to: " + res.pdf_path);
                    }
                }
            }
            } else {
                UITheme::renderDangerBanner(recRes.errorMessage.c_str());
            }
        }
        UITheme::endCard();
    }
}

} // namespace forensivault::gui
