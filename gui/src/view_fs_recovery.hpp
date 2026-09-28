#pragma once

#include "async_task.hpp"
#include <forensivault/fs_recovery.hpp>
#include <string>
#include <vector>

namespace forensivault::gui {

class ViewFsRecovery {
public:
    ViewFsRecovery();

    void render();

private:
    void renderInputs();
    void renderProbeResults();
    void renderRecoveryResults();

    char imagePathBuffer_[1024];
    char outputDirBuffer_[1024];
    int partitionOffset_ = 0;

    // Probe
    bool hasProbed_ = false;
    forensivault::api::VolumeMetadata probedVolume_;

    // Recovery Execution
    AsyncTaskRunner taskRunner_;
    bool hasRecoveryResult_ = false;
    forensivault::api::FilesystemRecoverySummary recoveryResult_;
};

} // namespace forensivault::gui
