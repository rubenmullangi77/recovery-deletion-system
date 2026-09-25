#include "sanitization/secure_folder_eraser.hpp"
#include "sanitization/system_protection.hpp"
#include "logging/audit_logger.hpp"
#include <filesystem>
#include <algorithm>

namespace fs = std::filesystem;

namespace forensivault {
namespace sanitization {

FolderEraseReport SecureFolderEraser::eraseFolder(
    const std::string& folderPath,
    SanitizationMethod method,
    ProgressCallback callback) {

    FolderEraseReport report;
    report.folder_path = folderPath;
    report.limitations = getMethodLimitations(method);

    // 1. Safety check
    std::string blockReason;
    if (SystemProtectionGuard::isProtected(folderPath, blockReason)) {
        report.success = false;
        report.details = "SECURITY INTERLOCK BLOCKED: " + blockReason;
        logging::AuditLogger::getInstance().logEvent(
            "SAFETY_BLOCK", folderPath, getMethodDescription(method), "BLOCKED", report.details);
        return report;
    }

    std::error_code ec;
    if (!fs::exists(folderPath, ec) || !fs::is_directory(folderPath, ec)) {
        report.success = false;
        report.details = "Folder does not exist or is not a directory.";
        return report;
    }

    // 2. Discover all files, subdirectories, and special entries
    std::vector<std::string> allFiles;
    std::vector<std::string> allDirs;
    std::vector<std::string> otherEntries;
    uint64_t totalBytesAll = 0;

    // Grant owner permissions to root folder so scan won't fail
    fs::permissions(folderPath, fs::perms::owner_all, fs::perm_options::add, ec);

    for (const auto& entry : fs::recursive_directory_iterator(folderPath, fs::directory_options::skip_permission_denied, ec)) {
        std::error_code statEc;
        if (entry.is_regular_file(statEc)) {
            allFiles.push_back(entry.path().string());
            totalBytesAll += entry.file_size(statEc);
        } else if (entry.is_directory(statEc)) {
            allDirs.push_back(entry.path().string());
        } else {
            // Symlinks, fifos, sockets, character/block devices
            otherEntries.push_back(entry.path().string());
        }
    }

    // Sort subdirectories by depth (deepest first)
    std::sort(allDirs.begin(), allDirs.end(), [](const std::string& a, const std::string& b) {
        return a.length() > b.length();
    });

    uint64_t bytesProcessedSoFar = 0;
    size_t fileIdx = 0;

    // 3. Multi-pass overwrite & scrub each regular file
    for (const auto& filePath : allFiles) {
        fileIdx++;
        uint64_t curFileSize = 0;
        try { curFileSize = fs::file_size(filePath); } catch (...) {}

        // Ensure file is writable before shredding
        std::error_code permEc;
        fs::permissions(filePath, fs::perms::owner_all, fs::perm_options::add, permEc);

        auto wrappedCb = [&](const EraseProgress& p) {
            if (callback) {
                EraseProgress agg = p;
                agg.current_file_index = fileIdx;
                agg.total_files = allFiles.size();
                agg.total_bytes_processed = bytesProcessedSoFar + p.bytes_processed_file;
                agg.total_bytes_all = totalBytesAll;
                agg.percentage = (totalBytesAll == 0) ? 100.0 :
                    (static_cast<double>(agg.total_bytes_processed) / totalBytesAll) * 100.0;
                callback(agg);
            }
        };

        auto res = file_eraser_.eraseFile(filePath, method, wrappedCb);
        report.file_verifications.push_back(res);

        if (res.is_verified) {
            report.files_erased++;
            report.total_bytes_erased += curFileSize;
            bytesProcessedSoFar += curFileSize;
        }
    }

    // 4. Remove special non-regular entries (symlinks, fifos, sockets)
    for (const auto& otherPath : otherEntries) {
        std::error_code rmEc;
        fs::permissions(otherPath, fs::perms::owner_all, fs::perm_options::add, rmEc);
        fs::remove(otherPath, rmEc);
    }

    // 5. Remove subdirectories from deepest to shallowest using remove_all
    for (const auto& dirPath : allDirs) {
        std::error_code rmEc;
        fs::permissions(dirPath, fs::perms::owner_all, fs::perm_options::add, rmEc);
        if (fs::remove_all(dirPath, rmEc) > 0 || !fs::exists(dirPath, rmEc)) {
            report.folders_removed++;
        }
    }

    // 6. Force-remove the root directory
    std::error_code rootEc;
    fs::permissions(folderPath, fs::perms::owner_all, fs::perm_options::add, rootEc);
    fs::remove_all(folderPath, rootEc);

    if (!fs::exists(folderPath, rootEc)) {
        report.folders_removed++;
        report.success = true;
        report.details = "Folder and all internal contents securely erased and verified.";
    } else {
        // If still exists, attempt single remove
        if (fs::remove(folderPath, rootEc) || !fs::exists(folderPath, rootEc)) {
            report.folders_removed++;
            report.success = true;
            report.details = "Folder and all internal contents securely erased and verified.";
        } else {
            report.success = false;
            report.details = "Files erased, but root folder removal encountered error: " + rootEc.message();
        }
    }

    logging::AuditLogger::getInstance().logEvent(
        "SECURE_FOLDER_ERASE",
        folderPath,
        getMethodDescription(method),
        report.success ? "SUCCESS" : "PARTIAL",
        report.details + " Erased " + std::to_string(report.files_erased) + " files, " +
            std::to_string(report.folders_removed) + " directories."
    );

    return report;
}

} // namespace sanitization
} // namespace forensivault
