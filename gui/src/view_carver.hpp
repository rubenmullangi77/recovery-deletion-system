#pragma once

#include "async_task.hpp"
#include <forensivault/carver.hpp>
#include <string>
#include <vector>

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
    bool hasResult_ = false;
    forensivault::api::CarveSessionResult finalResult_;
};

} // namespace forensivault::gui
