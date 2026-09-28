#pragma once

#include "async_task.hpp"
#include <forensivault/drive_sanitizer.hpp>
#include <string>
#include <vector>
#include <atomic>
#include <mutex>

namespace forensivault::gui {

class ViewDriveSanitizer {
public:
    ViewDriveSanitizer();

    void render();

private:
    void renderDeviceSelection();
    void renderControls();
    void renderProgressCard();
    void renderResultsCard();
    void renderConfirmationModal();

    char targetDriveBuffer_[1024];
    bool isSystemProtected_ = false;
    std::string protectionReason_;

    // Standards
    forensivault::api::DriveSanitizeStandard selectedStandard_ =
        forensivault::api::DriveSanitizeStandard::NIST_800_88_CLEAR;

    // Attached devices for quick selection
    std::vector<forensivault::api::StorageDeviceDescriptor> attachedDevices_;
    int selectedDeviceIdx_ = -1;

    // Confirmation Modal
    bool showConfirmModal_ = false;
    char confirmInputBuffer_[64];

    // Execution
    AsyncTaskRunner taskRunner_;
    std::atomic<bool> hasResult_{false};
    std::mutex resultMutex_;
    forensivault::api::DriveSanitizeResult finalResult_;
};

} // namespace forensivault::gui
