#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <memory>

namespace forensivault::recovery {

enum class DeletedItemSource {
    TRASH_JOURNAL,        // FreeDesktop Trash specification / Windows Recycle Bin (100% fidelity)
    FILESYSTEM_METADATA,  // FAT32 directory tables, exFAT stream extensions, NTFS $MFT
    CLUSTER_CARVED,       // Deep carving / signature scan of unallocated regions
    SANITIZED_AUDIT       // ForensiVault Audit Journal (NIST SP 800-88 / DoD overwritten, 0% recoverable)
};

struct ScannedDeletedItem {
    std::string id;
    std::string filename;
    std::string original_path;
    std::string relative_path;
    std::string extension;
    uint64_t size_bytes{0};
    bool is_directory{false};
    DeletedItemSource source{DeletedItemSource::TRASH_JOURNAL};
    int confidence_score{100};
    std::string confidence_level{"High"};
    std::string deletion_timestamp;
    std::string payload_location; // path to file in trash or cluster reference
    bool selected{true};
};

struct DirectoryMountInfo {
    std::string directory_path;
    std::string mount_point;
    std::string filesystem_type;
    std::string device_path;
    uint64_t total_bytes{0};
    uint64_t free_bytes{0};
    bool is_device_readable{false};
};

struct DirectoryScanOutput {
    bool success{false};
    std::string error_message;
    DirectoryMountInfo mount_info;
    std::vector<ScannedDeletedItem> items;
    uint64_t duration_ms{0};
};

struct DirectoryRecoveryOutput {
    bool success{false};
    std::string error_message;
    size_t requested_count{0};
    size_t recovered_count{0};
    uint64_t recovered_bytes{0};
    std::vector<std::string> recovered_files;
    std::vector<std::string> errors;
};

class DirectoryScanner {
public:
    DirectoryScanner() = default;
    ~DirectoryScanner() = default;

    /**
     * @brief Resolves mount point, filesystem type, and device path for any live directory.
     */
    static DirectoryMountInfo resolveMountInfo(const std::string& directoryPath);

    /**
     * @brief Scans a directory for previously deleted files/folders across discovery sources:
     *        1. FreeDesktop Trash / Windows Recycle Bin journals matching the directory.
     *        2. Volume filesystem deleted records (FAT32 0xE5 tombstones, exFAT stream extensions, NTFS $MFT unallocated).
     *        3. Unallocated carving candidates if device is directly readable.
     */
    static DirectoryScanOutput scanDirectory(const std::string& directoryPath);

    /**
     * @brief Recovers selected deleted items to the target output directory.
     *        Guarantees non-destructive extraction, SHA-256 verification, and audit logging.
     */
    static DirectoryRecoveryOutput recoverItems(const std::string& directoryPath,
                                               const std::vector<ScannedDeletedItem>& itemsToRecover,
                                               const std::string& outputDirectory);

    /**
     * @brief URL-decodes percent-encoded characters (%20, etc.) commonly used in FreeDesktop Trash paths.
     */
    static std::string urlDecode(const std::string& str);

private:
    static std::vector<ScannedDeletedItem> scanTrashJournals(const std::string& directoryPath, const DirectoryMountInfo& mountInfo);
    static std::vector<ScannedDeletedItem> scanFilesystemMetadata(const std::string& directoryPath, const DirectoryMountInfo& mountInfo);
    static std::vector<ScannedDeletedItem> scanSanitizedAuditRecords(const std::string& directoryPath);
};

} // namespace forensivault::recovery
