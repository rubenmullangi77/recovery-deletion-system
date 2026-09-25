#pragma once

#include "sanitization/sanitization_types.hpp"
#include <string>
#include <vector>
#include <cstdint>

namespace forensivault {
namespace verification {

class EraseVerification {
public:
    EraseVerification() = default;

    /**
     * @brief Performs pre-unlink data verification on an overwritten file.
     * @param filepath Target file to inspect.
     * @param method The sanitization method applied.
     * @param expectedSize Expected size in bytes.
     * @return Detailed VerificationResult with entropy, pattern match rate, and limitations.
     */
    static sanitization::VerificationResult verifyOverwrittenFile(
        const std::string& filepath,
        sanitization::SanitizationMethod method,
        uint64_t expectedSize);

    /**
     * @brief Checks post-deletion accessibility of the file on the filesystem.
     * @param filepath Path that was supposedly deleted.
     * @return True if securely inaccessible (file does not exist), false if still accessible.
     */
    static bool verifyInaccessible(const std::string& filepath);
};

} // namespace verification
} // namespace forensivault
