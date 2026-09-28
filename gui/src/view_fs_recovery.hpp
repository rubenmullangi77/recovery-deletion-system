#pragma once

#include "async_task.hpp"
#include <forensivault/fs_recovery.hpp>
#include <forensivault/directory_recovery.hpp>
#include <string>
#include <vector>
#include <atomic>
#include <mutex>

namespace forensivault::gui {

class ViewFsRecovery {
public:
    ViewFsRecovery();

    void render();

private:
    void renderModeSelector();
    void renderDirectoryRecovery();
    void renderImageRecovery();
    void renderProbeResults();
    void renderRecoveryResults();

    // Mode: 0 = Live Directory & Drive Scan, 1 = Forensic Disk Image
    int recoveryMode_ = 0;

    // --- Mode 0: Live Directory Scan & Recovery ---
    char targetDirBuffer_[1024];
    char dirOutputDirBuffer_[1024];
    bool hasDirScanResult_ = false;
    forensivault::api::DirectoryScanResult dirScanResult_;
    std::mutex dirScanMutex_;
    std::atomic<bool> isDirScanning_{false};

    bool hasDirRecoveryResult_ = false;
    forensivault::api::DirectoryRecoveryResult dirRecoveryResult_;
    std::mutex dirRecoveryMutex_;
    std::atomic<bool> isDirRecovering_{false};

    // --- Mode 1: Forensic Disk Image Recovery ---
    char imagePathBuffer_[1024];
    char outputDirBuffer_[1024];
    int partitionOffset_ = 0;

    bool hasProbed_ = false;
    forensivault::api::VolumeMetadata probedVolume_;

    std::atomic<bool> hasRecoveryResult_{false};
    std::mutex recoveryMutex_;
    forensivault::api::FilesystemRecoverySummary recoveryResult_;

    AsyncTaskRunner taskRunner_;
};

} // namespace forensivault::gui
