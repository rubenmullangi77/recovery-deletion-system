#pragma once

#include "sanitization/sanitization_strategy.hpp"
#include <string>
#include <vector>
#include <cstdint>

namespace forensivault {
namespace sanitization {

struct SanitizationVerificationResult {
    bool verified{false};
    std::string post_wipe_hash;
    double measured_entropy{0.0};
    double match_rate_percentage{0.0};
    std::string details;
    std::vector<std::string> limitations;
};

class SanitizationVerifier {
public:
    SanitizationVerifier() = default;

    /**
     * @brief Cryptographically and statistically verifies a sanitized disk image.
     * @param imagePath Path to the sanitized disk image.
     * @param strategy The sanitization strategy that was applied.
     * @param preWipeHash The SHA-256 hash before sanitization occurred.
     * @return Comprehensive verification result with entropy and match rates.
     */
    static SanitizationVerificationResult verifyImage(
        const std::string& imagePath,
        const SanitizationStrategy& strategy,
        const std::string& preWipeHash);
};

} // namespace sanitization
} // namespace forensivault
