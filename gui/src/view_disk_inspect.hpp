#pragma once

#include "async_task.hpp"
#include <string>
#include <cstdint>

namespace forensivault::gui {

class ViewDiskInspect {
public:
    ViewDiskInspect();

    void render();

private:
    void renderInputs();
    void renderGeometry();
    void renderHashes();

    char imagePathBuffer_[1024];

    // Geometry data
    bool hasGeometry_ = false;
    std::string geomFilePath_;
    uint64_t geomTotalSize_ = 0;
    uint32_t geomSectorSize_ = 512;
    uint64_t geomTotalSectors_ = 0;
    bool geomHasMbr_ = false;
    std::string geomSector0Desc_;
    std::string geomError_;

    // Hashes
    AsyncTaskRunner hashRunner_;
    bool hasHashes_ = false;
    std::string sha256Hash_;
    std::string md5Hash_;
    std::string hashError_;
};

} // namespace forensivault::gui
