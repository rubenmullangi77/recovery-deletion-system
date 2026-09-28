#include "view_device_detector.hpp"
#include "ui_theme.hpp"
#include "app_context.hpp"

#include <imgui.h>
#include <iomanip>
#include <sstream>

namespace forensivault::gui {

ViewDeviceDetector::ViewDeviceDetector() {
    refreshDevices();
}

void ViewDeviceDetector::refreshDevices() {
    devices_ = forensivault::api::DriveSanitizerAPI::detectDevices();
    hasScanned_ = true;
}

void ViewDeviceDetector::render() {
    UITheme::renderCardHeader("STORAGE DEVICE DISCOVERY & HARDWARE INSPECTION",
                              "Physical Device Enumeration, NVMe/SATA/USB Discovery & Kernel Root Protections");

    if (!AppContext::getInstance().isElevated) {
        UITheme::renderWarningBanner("Running in Standard User Mode. Direct low-level physical drive enumeration and sector inspection require elevation.");
    }

    if (UITheme::beginCard("DevToolbarCard", "Hardware Bus Management", "SCAN CONTROLS", UITheme::COLOR_ORANGE)) {
        if (UITheme::renderPrimaryButton("Rescan Physical Storage Devices", ImVec2(280, 34))) {
            refreshDevices();
            AppContext::getInstance().postNotification(
                Notification::Type::INFO, "Hardware Scan",
                "Discovered " + std::to_string(devices_.size()) + " attached storage devices.");
        }

        ImGui::SameLine();
        ImGui::TextColored(UITheme::COLOR_TEXT_SECONDARY, "Total Attached Block Devices: %zu", devices_.size());
    }
    UITheme::endCard();

    if (devices_.empty()) {
        if (UITheme::beginCard("NoDevCard", nullptr, nullptr, UITheme::COLOR_ORANGE, 100.0f)) {
            ImGui::TextColored(UITheme::COLOR_YELLOW, "No physical block devices detected or access restricted by host operating system.");
        }
        UITheme::endCard();
        return;
    }

    for (size_t i = 0; i < devices_.size(); ++i) {
        const auto& dev = devices_[i];
        std::string cardId = "DevCard_" + std::to_string(i);

        const char* badge = dev.isSystemOrRootDrive ? "SYSTEM ROOT [LOCKED]" : "SAFE TO SANITIZE";
        ImVec4 badgeCol = dev.isSystemOrRootDrive ? UITheme::COLOR_RED : UITheme::COLOR_GREEN;

        if (UITheme::beginCard(cardId.c_str(), dev.deviceId.c_str(), badge, badgeCol)) {
            ImGui::Columns(3, nullptr, false);

            ImGui::Text("Device Model:   %s", dev.model.empty() ? "Generic Storage Block" : dev.model.c_str());
            ImGui::Text("Hardware Bus:   %s", dev.interfaceType.c_str());

            ImGui::NextColumn();

            ImGui::Text("Media Type:     %s", dev.mediaType.c_str());
            double gb = static_cast<double>(dev.sizeBytes) / (1024.0 * 1024.0 * 1024.0);
            ImGui::Text("Capacity:       %.2f GB (%llu bytes)", gb, static_cast<unsigned long long>(dev.sizeBytes));

            ImGui::NextColumn();

            if (dev.isSafeToSanitize) {
                std::string btnLabel = "Select for Sanitization##" + std::to_string(i);
                if (UITheme::renderPrimaryButton(btnLabel.c_str(), ImVec2(220, 32))) {
                    AppContext::getInstance().targetDriveForSanitization = dev.deviceId;
                    AppContext::getInstance().activeTab = ModuleTab::DRIVE_SANITIZER;
                }
            } else {
                UITheme::renderBadge("ROOT DRIVE - PERMANENTLY PROTECTED", UITheme::COLOR_RED);
            }

            ImGui::Columns(1);
        }
        UITheme::endCard();
    }
}

} // namespace forensivault::gui
