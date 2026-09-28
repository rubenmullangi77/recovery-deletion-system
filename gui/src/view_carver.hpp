#pragma once

#include "async_task.hpp"
#include <forensivault/carver.hpp>
#include <string>
#include <vector>
#include <atomic>
#include <mutex>

namespace forensivault::gui {

class ViewCarver {
public:
    ViewCarver();

    void render();

private:
    void renderInputs();
    void renderProgress();
    void renderSummary();
    void renderCarvedTable();

    char imagePathBuffer_[1024];
    char outputDirBuffer_[1024];
    float minConfidence_ = 30.0f;

    // Filter
    char searchFilterBuffer_[128];
    std::string selectedTypeFilter_ = "ALL";

    // Execution
    AsyncTaskRunner taskRunner_;
    std::atomic<bool> hasResult_{false};
    std::mutex resultMutex_;
    forensivault::api::CarveSessionResult finalResult_;
};

} // namespace forensivault::gui
