#pragma once

#include <string>
#include <vector>

namespace forensivault::gui {

class ViewRecoveredFiles {
public:
    ViewRecoveredFiles();
    void render();

private:
    char searchFilterBuffer_[128];
    int selectedSourceFilter_ = 0; // 0=All, 1=Carver, 2=Filesystem
    int selectedTypeFilter_ = 0;   // 0=All, 1=PDF, 2=Office, 3=Images, 4=Media
};

} // namespace forensivault::gui
