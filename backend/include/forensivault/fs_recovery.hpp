#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace forensivault::api {

enum class FilesystemType {
    UNKNOWN,
    FAT32,
    EXFAT,
    NTFS
};

struct RecoveredFileEntry {
    std::string filename;
    std::string extension;
    uint64_t sizeBytes = 0;
    bool isDeleted = false;
    uint64_t clusterOrMft = 0;
    std::string recoveredFilePath;
    std::string sha256;
};

struct VolumeMetadata {
    bool valid = false;
    FilesystemType type = FilesystemType::UNKNOWN;
    std::string label;
    uint32_t sectorSize = 512;
    uint32_t sectorsPerCluster = 8;
    uint64_t clusterSize = 4096;
    uint64_t totalClusters = 0;
};

struct FilesystemRecoverySummary {
    bool success = false;
    FilesystemType type = FilesystemType::UNKNOWN;
    VolumeMetadata volume;
    std::vector<RecoveredFileEntry> activeFiles;
    std::vector<RecoveredFileEntry> deletedFiles;
    std::string evidenceSha256;
    std::string errorMessage;
};

/**
 * @brief Public high-level C++ API for forensic filesystem metadata parsing and file recovery.
 */
class FsRecoveryAPI {
public:
    /**
     * @brief Probes a volume or disk image for supported filesystem structures (FAT32, exFAT, NTFS).
     */
    static VolumeMetadata probeVolume(const std::string& imagePath, uint64_t partitionOffset = 0);

    /**
     * @brief Parses filesystem metadata structures (FAT directory tables, exFAT stream extensions, NTFS $MFT)
     *        and extracts active files and deleted candidate files.
     */
    static FilesystemRecoverySummary recover(const std::string& imagePath,
                                            const std::string& outputDirectory = "",
                                            uint64_t partitionOffset = 0);
};

} // namespace forensivault::api
