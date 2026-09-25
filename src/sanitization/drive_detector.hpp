#pragma once

#include "sanitization/drive_types.hpp"
#include <string>
#include <vector>

namespace forensivault {
namespace sanitization {

class DriveDetector {
public:
    DriveDetector() = default;

    /**
     * @brief Detects geometry, partition structure, and capabilities of a disk image (.img, .dd).
     * @param imagePath Path to the raw disk image file.
     * @param simulatedType Optional simulated device type (HDD, SSD, USB, Memory Card).
     * @return Fully populated DriveProperties descriptor.
     */
    static DriveProperties detectImage(
        const std::string& imagePath,
        DriveMediaType simulatedType = DriveMediaType::DISK_IMAGE_RAW);

    /**
     * @brief Detects system physical storage devices and reports their capabilities.
     * In this prototype, physical drives are strictly flagged as is_safe_to_sanitize = false.
     * @return List of detected physical storage devices.
     */
    static std::vector<DriveProperties> detectPhysicalDevices();
};

} // namespace sanitization
} // namespace forensivault
