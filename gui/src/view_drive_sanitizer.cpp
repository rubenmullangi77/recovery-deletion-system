#include "view_drive_sanitizer.hpp"
#include "ui_theme.hpp"
#include "file_dialog.hpp"
#include "app_context.hpp"
#include <forensivault/core/platform.hpp>

#include <imgui.h>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <filesystem>

namespace fs = std::filesystem;

namespace forensivault::gui {

ViewDriveSanitizer::ViewDriveSanitizer() {
    std::memset(targetDriveBuffer_, 0, sizeof(targetDriveBuffer_));
    std::memset(confirmInputBuffer_, 0, sizeof(confirmInputBuffer_));
}

void ViewDriveSanitizer::render() {
    UITheme::renderCardHeader("CERTIFIED DRIVE & MEDIA SANITIZER",
                              "Hardware Block Sanitization for Physical HDDs, SSDs, Flash Media & Virtual Disk Images (NIST SP 800-88 & DoD 5220.22-M)");

    if (!AppContext::getInstance().targetDriveForSanitization.empty()) {
        std::strncpy(targetDriveBuffer_, AppContext::getInstance().targetDriveForSanitization.c_str(), sizeof(targetDriveBuffer_) - 1);
        AppContext::getInstance().targetDriveForSanitization.clear();
    }

    renderDeviceSelection();

    if (isSystemProtected_) {
        std::string warn = "CRITICAL HARDWARE SAFETY BLOCK: " + protectionReason_ +
                           " Sanitizing the active OS root or boot drive is strictly prohibited.";
        UITheme::renderDangerBanner(warn.c_str());
    }

    if (!AppContext::getInstance().isElevated) {
        UITheme::renderWarningBanner("Running in Standard User Security Context. Direct raw hardware access to physical drives requires Administrator elevation.");
    }

    renderControls();

    if (taskRunner_.isRunning()) {
        renderProgressCard();
    }

    if (hasResult_) {
        renderResultsCard();
    }

    renderConfirmationModal();
}

void ViewDriveSanitizer::renderDeviceSelection() {
    if (UITheme::beginCard("DriveSelectCard", "Storage Device / Image Selection", "DRIVE TARGET", UITheme::COLOR_ORANGE)) {
        ImGui::Text("Target Disk Image or Block Device Path (e.g. \\\\.\\PhysicalDrive1 or /evidence/drive.dd):");
        bool browseClicked = false, refreshClicked = false;
        UITheme::renderInputWithTwoButtons("##TargetDrive", targetDriveBuffer_, sizeof(targetDriveBuffer_),
                                           "Browse Image...", 130.0f, &browseClicked,
                                           "Refresh Drives", 130.0f, &refreshClicked);

        bool changed = false;
        if (browseClicked) {
            std::string selected = FileDialog::openFile("Select Disk Image", "Disk Images (*.img;*.dd;*.raw;*.iso;*.bin)", "*.img;*.dd;*.raw;*.iso;*.bin;*.*");
            if (!selected.empty()) {
                std::strncpy(targetDriveBuffer_, selected.c_str(), sizeof(targetDriveBuffer_) - 1);
                changed = true;
            }
        }
        if (refreshClicked) {
            attachedDevices_ = forensivault::api::DriveSanitizerAPI::detectDevices();
        }

        if (!attachedDevices_.empty()) {
            ImGui::Spacing();
            ImGui::Text("Or select from detected physical/removable devices:");
            const char* comboPreview = (selectedDeviceIdx_ >= 0 && selectedDeviceIdx_ < static_cast<int>(attachedDevices_.size()))
                ? attachedDevices_[selectedDeviceIdx_].name.c_str() : "Select attached physical device...";

            if (ImGui::BeginCombo("##DeviceCombo", comboPreview)) {
                for (int i = 0; i < static_cast<int>(attachedDevices_.size()); ++i) {
                    const auto& dev = attachedDevices_[i];
                    bool isSelected = (selectedDeviceIdx_ == i);
                    std::string label = dev.deviceId + " - " + dev.name + " (" +
                        std::to_string(dev.sizeBytes / (1024 * 1024 * 1024)) + " GB)" +
                        (dev.isSystemOrRootDrive ? " [SYSTEM - PROTECTED]" : "");

                    if (ImGui::Selectable(label.c_str(), isSelected)) {
                        selectedDeviceIdx_ = i;
                        std::strncpy(targetDriveBuffer_, dev.deviceId.c_str(), sizeof(targetDriveBuffer_) - 1);
                        changed = true;
                    }
                    if (isSelected) {
                        ImGui::SetItemDefaultFocus();
                    }
                }
                ImGui::EndCombo();
            }
        }

        if (changed) {
            hasResult_ = false;
            isSystemProtected_ = false;
            fs::path p(targetDriveBuffer_);
            if (forensivault::core::Platform::isRootOrSystemPath(p) ||
                forensivault::core::Platform::isMainSystemDrive(p)) {
                isSystemProtected_ = true;
                protectionReason_ = "Target device matches the active system drive (" + p.string() + ").";
            }
        }
    }
    UITheme::endCard();
}

void ViewDriveSanitizer::renderControls() {
    if (UITheme::beginCard("DriveAlgoCard", "Sanitization Standard & Method", "COMPLIANCE METHOD", UITheme::COLOR_ORANGE)) {
        ImGui::TextColored(UITheme::COLOR_TEXT_PRIMARY, "Select Certified Overwrite Standard:");
        ImGui::Spacing();
        int stdIdx = static_cast<int>(selectedStandard_);
        ImGui::RadioButton("NIST SP 800-88 Rev 1 Clear (Single-Pass 0x00 with Sampling Verification) [Recommended]", &stdIdx, 0);
        ImGui::Spacing();
        ImGui::RadioButton("DoD 5220.22-M 3-Pass (0x00, 0xFF, PRNG + Lead/Median/Tail Sector Readback)", &stdIdx, 1);
        ImGui::Spacing();
        ImGui::RadioButton("Pseudorandom (1-Pass Cryptographic Hardware PRNG Overwrite)", &stdIdx, 2);
        selectedStandard_ = static_cast<forensivault::api::DriveSanitizeStandard>(stdIdx);

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        bool canSanitize = strlen(targetDriveBuffer_) > 0 && !isSystemProtected_ && !taskRunner_.isRunning();

        if (!canSanitize) ImGui::BeginDisabled();

        if (UITheme::renderDestructiveButton("Execute Certified Drive Sanitization...", ImVec2(320, 38))) {
            showConfirmModal_ = true;
            std::memset(confirmInputBuffer_, 0, sizeof(confirmInputBuffer_));
        }

        if (!canSanitize) ImGui::EndDisabled();
    }
    UITheme::endCard();
}

void ViewDriveSanitizer::renderProgressCard() {
    if (UITheme::beginCard("DriveProgressCard", "Drive Overwrite Execution", "ACTIVE WORKER", UITheme::COLOR_ORANGE)) {
        UITheme::renderProgressBar(taskRunner_.getProgress(), taskRunner_.getStatusText().c_str(), taskRunner_.getSubStatusText().c_str());
    }
    UITheme::endCard();
}

void ViewDriveSanitizer::renderResultsCard() {
    forensivault::api::DriveSanitizeResult res;
    {
        std::lock_guard<std::mutex> lock(resultMutex_);
        res = finalResult_;
    }

    if (UITheme::beginCard("DriveResultsCard", "Sanitization & Sector Verification Certificate",
                           res.success ? "VERIFIED COMPLIANT" : "SANITIZATION FAILED",
                           res.success ? UITheme::COLOR_GREEN : UITheme::COLOR_RED)) {
        if (res.success) {
            UITheme::renderSuccessBanner("All target sectors overwritten and lead/median/tail sampling verification confirmed non-recoverable.");
            ImGui::Columns(3, nullptr, false);
            double gb = static_cast<double>(res.totalBytesSanitized) / (1024.0 * 1024.0 * 1024.0);
            UITheme::renderWrappedText("Bytes Sanitized:", UITheme::COLOR_TEXT_MUTED);
            UITheme::renderWrappedFormatted(UITheme::COLOR_TEXT_PRIMARY, "%.2f GB (%llu bytes)", gb, static_cast<unsigned long long>(res.totalBytesSanitized));
            ImGui::Spacing();
            UITheme::renderWrappedText("Passes Completed:", UITheme::COLOR_TEXT_MUTED);
            UITheme::renderWrappedFormatted(UITheme::COLOR_TEXT_PRIMARY, "%d passes", res.passesCompleted);

            ImGui::NextColumn();
            UITheme::renderWrappedText("Compliance Standard:", UITheme::COLOR_TEXT_MUTED);
            UITheme::renderWrappedText("NIST SP 800-88 / DoD 5220.22-M", UITheme::COLOR_TEXT_PRIMARY);
            ImGui::Spacing();
            UITheme::renderWrappedText("Sector Verification:", UITheme::COLOR_TEXT_MUTED);
            UITheme::renderWrappedText(res.verificationPassed ? "[CONFIRMED COMPLIANT]" : "[UNVERIFIED]",
                                       res.verificationPassed ? UITheme::COLOR_GREEN : UITheme::COLOR_YELLOW);

            ImGui::NextColumn();
            UITheme::renderWrappedText("Duration:", UITheme::COLOR_TEXT_MUTED);
            UITheme::renderWrappedFormatted(UITheme::COLOR_TEXT_PRIMARY, "%.2f seconds", res.durationSeconds);
            ImGui::Spacing();
            if (!res.auditSignature.empty()) {
                UITheme::renderWrappedText("Audit Signature:", UITheme::COLOR_TEXT_MUTED);
                UITheme::renderWrappedFormatted(UITheme::COLOR_TEXT_PRIMARY, "%s...", res.auditSignature.substr(0, 16).c_str());
            }
            ImGui::Columns(1);
        } else {
            UITheme::renderDangerBanner(res.errorMessage.c_str());
        }
    }
    UITheme::endCard();
}

void ViewDriveSanitizer::renderConfirmationModal() {
    if (showConfirmModal_) {
        ImGui::OpenPopup("Permanent Drive Destruction Warning");
    }

    ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSizeConstraints(ImVec2(480, 240), ImVec2(720, 800));

    if (ImGui::BeginPopupModal("Permanent Drive Destruction Warning", &showConfirmModal_, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::TextColored(UITheme::COLOR_RED, "CRITICAL WARNING: PERMANENT STORAGE DEVICE ERASURE");
        ImGui::Separator();
        ImGui::Spacing();
        UITheme::renderWrappedText("This will irreversibly overwrite ALL addressable sectors on the target storage device. "
                           "Every partition table, file system, boot record, and unallocated cluster will be erased.", UITheme::COLOR_TEXT_SECONDARY);
        ImGui::Spacing();
        UITheme::renderWrappedFormatted(UITheme::COLOR_TEXT_PRIMARY, "Target Device: %s", targetDriveBuffer_);
        ImGui::Spacing();
        ImGui::TextColored(UITheme::COLOR_TEXT_PRIMARY, "Type 'DESTROY' in uppercase to authorize drive sanitization:");

        ImGui::SetNextItemWidth(-1);
        ImGui::InputText("##DriveDestroyConfirm", confirmInputBuffer_, sizeof(confirmInputBuffer_));

        bool matches = (std::strcmp(confirmInputBuffer_, "DESTROY") == 0);

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        if (!matches) ImGui::BeginDisabled();

        if (UITheme::renderDestructiveButton("PERMANENTLY DESTROY DRIVE", ImVec2(260, 38))) {
            showConfirmModal_ = false;
            hasResult_ = false;

            std::string target = targetDriveBuffer_;
            auto stdChoice = selectedStandard_;

            AppContext::getInstance().currentOperation.start(
                "Drive Sanitizer",
                (stdChoice == forensivault::api::DriveSanitizeStandard::NIST_800_88_CLEAR ? "NIST SP 800-88 Clear" : "DoD 5220.22-M 3-Pass"),
                target, "");

            taskRunner_.run([this, target, stdChoice]() {
                auto cb = [this](const forensivault::api::DriveSanitizeProgress& prg) {
                    float frac = static_cast<float>(prg.percentComplete / 100.0);
                    std::ostringstream ss;
                    ss << "Pass " << prg.currentPass << "/" << prg.totalPasses
                       << " (" << std::fixed << std::setprecision(1) << prg.percentComplete << "%)";
                    std::ostringstream sub;
                    sub << "Speed: " << std::fixed << std::setprecision(2) << prg.currentSpeedMBps << " MB/s";
                    taskRunner_.setProgress(frac, ss.str(), sub.str());
                    AppContext::getInstance().currentOperation.update(frac, ss.str(), sub.str());
                };

                auto res = forensivault::api::DriveSanitizerAPI::sanitize(target, stdChoice, cb);
                {
                    std::lock_guard<std::mutex> lock(resultMutex_);
                    finalResult_ = res;
                }
                hasResult_.store(true);

                if (res.success) {
                    AppContext::getInstance().totalDrivesSanitized++;
                    std::string summary = "Sanitized " + std::to_string(res.totalBytesSanitized / (1024 * 1024)) + " MB.";
                    AppContext::getInstance().currentOperation.finish(true, summary);
                    AppContext::getInstance().postNotification(
                        Notification::Type::SUCCESS, "Drive Sanitization Complete",
                        "Target device verified sanitized.");
                } else {
                    AppContext::getInstance().currentOperation.finish(false, res.errorMessage);
                    AppContext::getInstance().postNotification(
                        Notification::Type::FAILURE, "Drive Sanitization Failed",
                        res.errorMessage);
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
