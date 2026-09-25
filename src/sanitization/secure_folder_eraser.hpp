#pragma once

#include "sanitization/sanitization_types.hpp"
#include "sanitization/secure_file_eraser.hpp"
#include <string>
#include <vector>

namespace forensivault {
namespace sanitization {

struct FolderEraseReport {
    std::string folder_path;
    size_t files_erased{0};
    size_t folders_removed{0};
    uint64_t total_bytes_erased{0};
    bool success{false};
    std::string details;
    std::vector<VerificationResult> file_verifications;
    std::vector<std::string> limitations;
};

class SecureFolderEraser {
public:
    SecureFolderEraser() = default;

    /**
     * @brief Recursively sanitizes all files and directories within a folder.
     * @param folderPath Directory to sanitize and remove.
     * @param method Sanitization standard to apply.
     * @param callback Optional progress reporting callback.
     * @return FolderEraseReport detailing all erased items and verifications.
     */
    FolderEraseReport eraseFolder(
        const std::string& folderPath,
        SanitizationMethod method = SanitizationMethod::NIST_800_88_CLEAR,
        ProgressCallback callback = nullptr);

private:
    SecureFileEraser file_eraser_;
};

} // namespace sanitization
} // namespace forensivault
