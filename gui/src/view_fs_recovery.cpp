#include "view_fs_recovery.hpp"
#include "ui_theme.hpp"
#include "file_dialog.hpp"
#include "app_context.hpp"

#include <imgui.h>
#include <cstring>
#include <sstream>
#include <filesystem>

namespace fs = std::filesystem;

namespace forensivault::gui {

ViewFsRecovery::ViewFsRecovery() {
    std::memset(imagePathBuffer_, 0, sizeof(imagePathBuffer_));
    std::strncpy(outputDirBuffer_, "recovered/filesystem", sizeof(outputDirBuffer_) - 1);
}

void ViewFsRecovery::render() {
    UITheme::renderCardHeader("FILESYSTEM METADATA RECOVERY",
                              "Volume Structure & Directory Table Reconstruction for FAT32, exFAT Stream Extensions & NTFS Master File Table ($MFT)");

    renderInputs();

    if (hasProbed_) {
        renderProbeResults();
    }

    if (taskRunner_.isRunning()) {
        if (UITheme::beginCard("FsProgressCard", "Parsing Filesystem Metadata", "RUNNING", UITheme::COLOR_BLUE)) {
            UITheme::renderProgressBar(-1.0f * (float)ImGui::GetTime(), "Parsing directory tables and unallocated MFT records...", "Extracting file records and validating cluster chains...");
        }
        UITheme::endCard();
    }

    if (hasRecoveryResult_) {
        renderRecoveryResults();
    }
}

void ViewFsRecovery::renderInputs() {
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
                recoveryResult_ = forensivault::api::FsRecoveryAPI::recover(img, out, off);
                hasRecoveryResult_ = true;

                if (recoveryResult_.success) {
                    for (const auto& df : recoveryResult_.deletedFiles) {
                        AppContext::getInstance().registerFsFile(
                            df.filename, df.recoveredFilePath, off, df.sizeBytes, "Recovered");
                    }
                    for (const auto& af : recoveryResult_.activeFiles) {
                        AppContext::getInstance().registerFsFile(
                            af.filename, af.recoveredFilePath, off, af.sizeBytes, "Active");
                    }

                    std::string summary = "Extracted " + std::to_string(recoveryResult_.activeFiles.size()) + " active, " +
                                          std::to_string(recoveryResult_.deletedFiles.size()) + " deleted files.";
                    AppContext::getInstance().currentOperation.finish(true, summary);
                    AppContext::getInstance().postNotification(
                        Notification::Type::SUCCESS, "Filesystem Recovery Complete", summary);
                } else {
                    AppContext::getInstance().currentOperation.finish(false, recoveryResult_.errorMessage);
                    AppContext::getInstance().postNotification(
                        Notification::Type::FAILURE, "Recovery Failed",
                        recoveryResult_.errorMessage);
                }
            });
        }

        if (!canProbe) ImGui::EndDisabled();
    }
    UITheme::endCard();
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
            ImGui::Text("Volume Type:      %s", fsName.c_str());
            ImGui::Text("Volume Label:     %s", probedVolume_.label.empty() ? "(None)" : probedVolume_.label.c_str());
            ImGui::NextColumn();
            ImGui::Text("Sector Size:      %u bytes", probedVolume_.sectorSize);
            ImGui::Text("Cluster Size:     %llu bytes", static_cast<unsigned long long>(probedVolume_.clusterSize));
            ImGui::NextColumn();
            ImGui::Text("Sectors/Cluster:  %u", probedVolume_.sectorsPerCluster);
            ImGui::Text("Total Clusters:   %llu", static_cast<unsigned long long>(probedVolume_.totalClusters));
            ImGui::Columns(1);
        } else {
            UITheme::renderWarningBanner("No standard FAT32, exFAT, or NTFS signature detected at the specified offset. Verify partition alignment or switch to Module 3 (Raw Data Carving).");
        }
    }
    UITheme::endCard();
}

void ViewFsRecovery::renderRecoveryResults() {
    if (UITheme::beginCard("FsResultsCard", "Filesystem Extraction Summary",
                           recoveryResult_.success ? "SUCCESS" : "FAILED",
                           recoveryResult_.success ? UITheme::COLOR_GREEN : UITheme::COLOR_RED)) {
        if (recoveryResult_.success) {
            ImGui::Columns(3, nullptr, false);
            ImGui::Text("Active Files:   %zu", recoveryResult_.activeFiles.size());
            ImGui::NextColumn();
            ImGui::Text("Deleted Files:  %zu (Tombstones recovered)", recoveryResult_.deletedFiles.size());
            ImGui::NextColumn();
            if (!recoveryResult_.evidenceSha256.empty()) {
                ImGui::TextDisabled("Evidence Hash: %s...", recoveryResult_.evidenceSha256.substr(0, 16).c_str());
            }
            ImGui::Columns(1);
        } else {
            UITheme::renderDangerBanner(recoveryResult_.errorMessage.c_str());
        }
    }
    UITheme::endCard();

    if (!recoveryResult_.deletedFiles.empty()) {
        if (UITheme::beginCard("FsDelTableCard", "Recovered Deleted Files", "DELETED ENTRIES", UITheme::COLOR_BLUE)) {
            if (ImGui::BeginTable("DeletedFilesTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, 200))) {
                ImGui::TableSetupColumn("Filename", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Ext", ImGuiTableColumnFlags_WidthFixed, 70.0f);
                ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                ImGui::TableSetupColumn("Extracted Path", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableHeadersRow();

                for (const auto& df : recoveryResult_.deletedFiles) {
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    ImGui::TextColored(UITheme::COLOR_YELLOW, "[DEL] %s", df.filename.c_str());

                    ImGui::TableSetColumnIndex(1);
                    ImGui::Text("%s", df.extension.c_str());

                    ImGui::TableSetColumnIndex(2);
                    if (df.sizeBytes < 1024) {
                        ImGui::Text("%llu B", static_cast<unsigned long long>(df.sizeBytes));
                    } else if (df.sizeBytes < 1024 * 1024) {
                        ImGui::Text("%.1f KB", df.sizeBytes / 1024.0);
                    } else {
                        ImGui::Text("%.2f MB", df.sizeBytes / (1024.0 * 1024.0));
                    }

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
