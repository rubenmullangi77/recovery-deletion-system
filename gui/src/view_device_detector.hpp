#pragma once

#include <forensivault/drive_sanitizer.hpp>
#include <vector>

namespace forensivault::gui {

class ViewDeviceDetector {
public:
    ViewDeviceDetector();

    void render();

private:
    void refreshDevices();

    std::vector<forensivault::api::StorageDeviceDescriptor> devices_;
    bool hasScanned_ = false;
};

} // namespace forensivault::gui
