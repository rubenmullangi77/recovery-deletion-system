#pragma once

#include "async_task.hpp"
#include <string>

namespace forensivault::gui {

class ViewSettingsAbout {
public:
    ViewSettingsAbout();
    void render();

private:
    void renderThemeSettings();
    void renderComplianceSpecs();
    void renderSecurityContext();
    void renderCryptoBenchmark();
    void renderAboutPlatform();

    int testSizeMb_ = 64;
    AsyncTaskRunner benchRunner_;
    bool hasBenchResult_ = false;
    double sha256SpeedMBps_ = 0.0;
    double md5SpeedMBps_ = 0.0;
    double sha256TimeMs_ = 0.0;
    double md5TimeMs_ = 0.0;
};

} // namespace forensivault::gui
