#pragma once

#include "async_task.hpp"
#include <forensivault/file_eraser.hpp>
#include <string>
#include <vector>
#include <filesystem>
#include <atomic>
#include <mutex>

namespace forensivault::gui {

class ViewFileEraser {
public:
    ViewFileEraser();

    void render();

private:
    void renderTargetSelection();
    void renderDirectoryInspector();
    void renderPreviewCard();
    void renderActionControls();
    void renderProgressCard();
    void renderResultsCard();
    void renderConfirmationModal();

    char targetPathBuffer_[1024];
    std::string currentInspectedPath_;
    bool isDirectory_ = false;
    bool isSystemProtected_ = false;
    std::string protectionReason_;

    // Directory items selection
    struct DirItem {
        std::filesystem::path path;
        std::string filename;
        bool isDir = false;
        uint64_t sizeBytes = 0;
        bool selected = true;
    };
    std::vector<DirItem> dirItems_;
    bool sanitizeEntireDirectory_ = true;

    // Standard
    forensivault::api::EraseMethod selectedMethod_ = forensivault::api::EraseMethod::NIST_800_88_CLEAR;

    // Preview
    bool hasPreview_ = false;
    forensivault::api::ErasePreviewReport previewReport_;

    // Modal
    bool showConfirmModal_ = false;
    char confirmInputBuffer_[64];

    // Background Execution
    AsyncTaskRunner taskRunner_;
    forensivault::api::EraseProgress liveProgress_;
    std::atomic<bool> hasFinishedResult_{false};
    std::mutex resultsMutex_;
    forensivault::api::EraseResult finalResult_;
    uint64_t totalErasedFiles_ = 0;
    uint64_t totalErasedDirs_ = 0;
    uint64_t totalErasedBytes_ = 0;
    int maxPassesCompleted_ = 0;
    std::string lastAuditSignature_;
    std::vector<std::string> executionErrors_;
};

} // namespace forensivault::gui
