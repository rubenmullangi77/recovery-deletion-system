#pragma once

#include "sanitization/sanitization_types.hpp"
#include "verification/erase_verification.hpp"
#include <string>
#include <vector>
#include <cstdint>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

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

#if defined(_WIN32)
    static bool secureUnlink(
        HANDLE hFile,
        const TargetIdentity& id,
        const std::string& filepath);
#else
    static bool secureUnlink(
        int fd,
        const TargetIdentity& id,
        const std::string& filepath);
#endif

private:
#if defined(_WIN32)
    bool overwritePayload(
        HANDLE hFile,
        uint64_t fileSize,
        SanitizationMethod method,
        ProgressCallback callback,
        const std::string& filepath);

    VerificationResult verifyHandle(
        HANDLE hFile,
        uint64_t expectedSize,
        SanitizationMethod method,
        const std::string& preWipeSampleHash,
        const TargetIdentity& id);
#else
    bool overwritePayload(
        int fd,
        uint64_t fileSize,
        SanitizationMethod method,
        ProgressCallback callback,
        const std::string& filepath);

    VerificationResult verifyHandle(
        int fd,
        uint64_t expectedSize,
        SanitizationMethod method,
        const std::string& preWipeSampleHash,
        const TargetIdentity& id);
#endif
};

} // namespace sanitization
} // namespace forensivault
