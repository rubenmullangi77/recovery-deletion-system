#pragma once

#include "sanitization/sanitization_types.hpp"
#include "verification/erase_verification.hpp"
#include <string>
#include <vector>
#include <cstdint>

namespace forensivault {
namespace sanitization {

class SecureFileEraser {
public:
    SecureFileEraser() = default;

    /**
     * @brief Securely sanitizes and deletes an individual file according to standard.
     * @param filepath Path of file to sanitize.
     * @param method Sanitization standard to apply.
     * @param callback Optional progress reporting callback.
     * @return VerificationResult detailing overwritten verification and status.
     */
    VerificationResult eraseFile(
        const std::string& filepath,
        SanitizationMethod method = SanitizationMethod::NIST_800_88_CLEAR,
        ProgressCallback callback = nullptr);

    /**
     * @brief Number of passes required for a given sanitization method.
     */
    static int getPassCount(SanitizationMethod method);

private:
    bool overwritePayload(
        const std::string& filepath,
        uint64_t fileSize,
        SanitizationMethod method,
        ProgressCallback callback);

    void shredMetadataAndUnlink(const std::string& filepath);
    std::string generateRandomName(size_t length);
};

} // namespace sanitization
} // namespace forensivault
