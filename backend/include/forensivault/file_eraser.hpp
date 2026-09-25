#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <functional>
#include <memory>

namespace forensivault::api {

enum class EraseMethod {
    NIST_800_88_CLEAR,     ///< NIST SP 800-88 Rev 1 Clear: Single pass zero-fill with hardware flush and read-back verification
    DOD_5220_22_M,         ///< DoD 5220.22-M: 3 passes (0x00, 0xFF, Cryptographic PRNG) with read-back verification
    PSEUDO_RANDOM          ///< Cryptographic PRNG random overwrite pass with verification
};

struct EraseProgress {
    std::string currentPath;
    uint64_t bytesProcessed = 0;
    uint64_t totalBytes = 0;
    double percentComplete = 0.0;
    int currentPass = 0;
    int totalPasses = 0;
};

using EraseProgressCallback = std::function<void(const EraseProgress& progress)>;

struct ErasePreviewItem {
    std::string path;
    bool isDirectory = false;
    uint64_t sizeBytes = 0;
};

struct ErasePreviewReport {
    bool isRootOrSystemProtected = false;
    std::string protectionReason;
    uint64_t totalFiles = 0;
    uint64_t totalDirectories = 0;
    uint64_t totalBytes = 0;
    std::vector<ErasePreviewItem> items;
};

struct EraseResult {
    bool success = false;
    std::string targetPath;
    uint64_t filesErased = 0;
    uint64_t directoriesErased = 0;
    uint64_t bytesErased = 0;
    int passesCompleted = 0;
    bool verificationPassed = false;
    std::string auditSignature;
    std::string errorMessage;
};

/**
 * @brief Public high-level C++ API for secure file and directory sanitization.
 *        Guarantees strict root drive protection and platform privilege enforcement.
 */
class FileEraserAPI {
public:
    /**
     * @brief Generates a non-destructive preview of items that would be targeted.
     */
    static ErasePreviewReport preview(const std::string& targetPath);

    /**
     * @brief Securely erases a single file in compliance with NIST SP 800-88 or DoD 5220.22-M.
     * @param filePath Absolute path of target file.
     * @param method Sanitization standard to apply.
     * @param cb Optional progress callback for GUI / CLI progress bars.
     */
    static EraseResult eraseFile(const std::string& filePath,
                                 EraseMethod method = EraseMethod::NIST_800_88_CLEAR,
                                 EraseProgressCallback cb = nullptr);

    /**
     * @brief Securely erases a directory and all nested contents recursively, wiping file metadata.
     * @param dirPath Absolute path of target directory.
     * @param method Sanitization standard to apply.
     * @param cb Optional progress callback for GUI / CLI progress bars.
     */
    static EraseResult eraseDirectory(const std::string& dirPath,
                                      EraseMethod method = EraseMethod::NIST_800_88_CLEAR,
                                      EraseProgressCallback cb = nullptr);
};

} // namespace forensivault::api
