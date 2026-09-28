#pragma once

#include "async_task.hpp"
#include <forensivault/directory_recovery.hpp>
#include <string>
#include <vector>
#include <atomic>
#include <mutex>

namespace forensivault::gui {

class ViewDirectoryRecovery {
public:
    ViewDirectoryRecovery();

    void render();

private:
    void renderDirectorySelector();
    void renderVolumeInfo(const forensivault::api::DirectoryVolumeInfo& volInfo);
    void renderDiscoveredItems();
    void renderRecoveryExecution();

    char targetDirBuffer_[1024];
    char outputDirBuffer_[1024];
    char searchFilterBuffer_[256];

    // Category filter: 0 = All, 1 = Documents, 2 = Images, 3 = Archives, 4 = Folders
    int categoryFilter_ = 0;

    // Scan state
    bool hasScanResult_ = false;
    forensivault::api::DirectoryScanResult scanResult_;
    std::mutex scanMutex_;
    std::atomic<bool> isScanning_{false};

    // Recovery state
    bool hasRecoveryResult_ = false;
    forensivault::api::DirectoryRecoveryResult recoveryResult_;
    std::mutex recoveryMutex_;
    std::atomic<bool> isRecovering_{false};

    AsyncTaskRunner taskRunner_;
};

} // namespace forensivault::gui
