#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace forensivault::api {

enum class DetectionSource {
    TRASH_JOURNAL,        // FreeDesktop Trash specification / Windows Recycle Bin (100% fidelity)
    FILESYSTEM_METADATA,  // FAT directory tables, exFAT stream extensions, NTFS $MFT
    CLUSTER_CARVED,       // Deep signature carving from unallocated space
    SANITIZED_AUDIT       // ForensiVault Audit Journal (NIST SP 800-88 / DoD overwritten, 0% recoverable)
};

struct DiscoveredDeletedItem {
    std::string id;
    std::string filename;
    std::string originalPath;
    std::string relativePath;
    std::string extension;
    uint64_t sizeBytes = 0;
    bool isDirectory = false;
    DetectionSource source = DetectionSource::TRASH_JOURNAL;
    int confidenceScore = 100;
    std::string confidenceLevel = "High";
    std::string deletionTimestamp;
    std::string payloadLocator;
    bool selected = true;
};

struct DirectoryVolumeInfo {
    std::string directoryPath;
    std::string mountPoint;
    std::string filesystemType;
    std::string devicePath;
    uint64_t totalBytes = 0;
    uint64_t freeBytes = 0;
    bool isDeviceReadable = false;
};

struct DirectoryScanResult {
    bool success = false;
    std::string errorMessage;
    DirectoryVolumeInfo volume;
    std::vector<DiscoveredDeletedItem> items;
    uint64_t scanDurationMs = 0;
};

struct DirectoryRecoveryResult {
    bool success = false;
    std::string errorMessage;
    size_t requestedCount = 0;
    size_t recoveredCount = 0;
    uint64_t recoveredBytes = 0;
    std::vector<std::string> recoveredFiles;
    std::vector<std::string> errors;
};

/**
 * @brief Public high-level C++ API for scanning live directories and recovering deleted files/folders.
 *        Maintains complete architectural decoupling between backend forensic logic and UI presentations.
 */
class DirectoryRecoveryAPI {
public:
    /**
     * @brief Resolves mount, device, and filesystem metadata for a given live directory.
     */
    static DirectoryVolumeInfo inspectDirectory(const std::string& directoryPath);

    /**
     * @brief Scans a directory for previously deleted files and folders.
     */
    static DirectoryScanResult scanDirectory(const std::string& directoryPath);

    /**
     * @brief Restores selected deleted items into the specified output destination directory.
     */
    static DirectoryRecoveryResult recoverItems(const std::string& directoryPath,
                                               const std::vector<DiscoveredDeletedItem>& itemsToRecover,
                                               const std::string& outputDirectory);
};

} // namespace forensivault::api
