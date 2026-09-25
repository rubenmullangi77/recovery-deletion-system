#pragma once

#include "sanitization/drive_types.hpp"
#include "sanitization/sanitization_strategy.hpp"
#include "sanitization/sanitization_verifier.hpp"
#include "sanitization/sanitization_types.hpp"
#include <string>
#include <vector>

namespace forensivault {
namespace sanitization {

class ImageSanitizer {
public:
    ImageSanitizer() = default;

    /**
     * @brief Executes certified secure sanitization on a target disk image file.
     * @param imagePath Path to the raw .img / .dd file.
     * @param strategy The sanitization strategy to apply.
     * @param confirmed Explicit confirmation boolean (must be true to proceed).
     * @param callback Optional progress callback for UI updates.
     * @return Full SanitizationReport with pre/post hashes, timestamps, and verifications.
     */
    SanitizationReport sanitizeImage(
        const std::string& imagePath,
        const SanitizationStrategy& strategy,
        bool confirmed,
        ProgressCallback callback = nullptr);

    /**
     * @brief Computes SHA-256 hash of a disk image file via streaming.
     */
    static std::string computeImageSha256(const std::string& imagePath);

private:
    static std::string currentTimestampIso();
};

} // namespace sanitization
} // namespace forensivault
