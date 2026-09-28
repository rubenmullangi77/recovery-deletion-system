#pragma once

namespace forensivault::gui {

class ViewOperationProgress {
public:
    ViewOperationProgress() = default;
    void render();

private:
    void renderActiveOperation();
    void renderIdleState();
};

} // namespace forensivault::gui
