#pragma once

namespace forensivault::gui {

class ViewDashboard {
public:
    ViewDashboard() = default;
    void render();

private:
    void renderMetricsOverview();
    void renderQuickLaunchModules();
    void renderForensicReadiness();
    void renderRecentOperations();
};

} // namespace forensivault::gui
