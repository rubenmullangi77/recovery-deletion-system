#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include <ostream>
#include "core/disk_image_reader.hpp"

namespace forensivault {
namespace filesystem {

enum class FsType {
    UNKNOWN = 0,
    FAT32,
    EXFAT,
    NTFS
};

inline std::ostream& operator<<(std::ostream& os, FsType type) {
    switch (type) {
        case FsType::FAT32: return os << "FAT32";
        case FsType::EXFAT: return os << "exFAT";
        case FsType::NTFS:  return os << "NTFS";
        default:            return os << "UNKNOWN";
    }
}

enum class AllocationStatus {
    ALLOCATED,           // Active, referenced in directory/MFT table as allocated
    DELETED_CANDIDATE,   // Tombstone record (e.g. 0xE5 in FAT, in-use bit 0 in exFAT/NTFS)
    DAMAGED_CHAIN,       // Metadata points to clusters that appear invalid or truncated
    NOT_RECOVERABLE,     // Required file data or allocation runs are destroyed/unavailable
    UNKNOWN
};

inline std::ostream& operator<<(std::ostream& os, AllocationStatus status) {
    switch (status) {
        case AllocationStatus::ALLOCATED:         return os << "ALLOCATED";
        case AllocationStatus::DELETED_CANDIDATE: return os << "DELETED_CANDIDATE";
        case AllocationStatus::DAMAGED_CHAIN:     return os << "DAMAGED_CHAIN";
        case AllocationStatus::NOT_RECOVERABLE:   return os << "NOT_RECOVERABLE";
        default:                                  return os << "UNKNOWN";
    }
}

enum class RecoveryMethod {
    FILESYSTEM_METADATA_ACTIVE,   // Recovered via active directory/MFT entry
    FILESYSTEM_METADATA_DELETED,  // Recovered via deleted directory/MFT candidate entry
    SIGNATURE_CARVED,             // Carved from unallocated/raw sectors without FS metadata
    HYBRID_VALIDATED              // Metadata candidate verified with signature validator
};

inline std::ostream& operator<<(std::ostream& os, RecoveryMethod method) {
    switch (method) {
        case RecoveryMethod::FILESYSTEM_METADATA_ACTIVE:  return os << "FILESYSTEM_METADATA_ACTIVE";
        case RecoveryMethod::FILESYSTEM_METADATA_DELETED: return os << "FILESYSTEM_METADATA_DELETED";
        case RecoveryMethod::SIGNATURE_CARVED:            return os << "SIGNATURE_CARVED";
        case RecoveryMethod::HYBRID_VALIDATED:             return os << "HYBRID_VALIDATED";
        default:                                          return os << "UNKNOWN";
    }
}

struct ClusterRun {
    uint64_t start_cluster{0};
    uint64_t cluster_count{0};
};

struct FsVolumeInfo {
    FsType fs_type{FsType::UNKNOWN};
    std::string volume_label;
    uint32_t serial_number{0};
    uint32_t bytes_per_sector{512};
    uint32_t sectors_per_cluster{8};
    uint64_t cluster_size{4096};
    uint64_t total_sectors{0};
    uint64_t total_clusters{0};
    uint64_t free_clusters{0};
    uint64_t partition_offset_bytes{0};
    uint64_t root_dir_offset_bytes{0};
    uint64_t allocation_table_offset{0};
    bool valid{false};
};

struct FsFileRecord {
    std::string filename;
    std::string extension;
    std::string full_path;
    uint64_t file_size{0};
    uint64_t starting_cluster{0};
    uint64_t byte_offset{0};
    bool is_directory{false};
    uint32_t attributes{0}; // Read-only, Hidden, System, Archive, etc.
    
    // Timestamps (represented as ISO formatted string or raw)
    std::string created_time;
    std::string modified_time;
    std::string accessed_time;

    AllocationStatus allocation_status{AllocationStatus::UNKNOWN};
    RecoveryMethod recovery_method{RecoveryMethod::FILESYSTEM_METADATA_ACTIVE};
    std::vector<ClusterRun> cluster_runs;
    
    // Recovery analysis metrics
    int confidence_score{0};
    std::string format_validation_status;
    std::string sha256_hash;

    // Forensic metadata extensions
    uint64_t mft_record_number{0};
    uint32_t fragment_count{0};
    bool is_recoverable{true};
    std::string unrecoverable_reason;
};

class FilesystemAnalyzer {
public:
    virtual ~FilesystemAnalyzer() = default;

    // Probe the disk image to check if this analyzer matches the filesystem at partitionStartSector
    virtual bool probe(core::DiskImageReader& reader, uint64_t partitionStartSector = 0) = 0;

    // Retrieve parsed volume geometry and filesystem metadata
    virtual FsVolumeInfo getVolumeInfo() const = 0;

    // Enumerate active files in root or specific directory path
    virtual std::vector<FsFileRecord> listDirectory(const std::string& path = "/") = 0;

    // Enumerate deleted-file candidates preserved in directory structures or MFT
    virtual std::vector<FsFileRecord> findDeletedFiles() = 0;

    // Extract raw file content using filesystem metadata (cluster runs or resident data)
    virtual std::vector<uint8_t> extractFile(const FsFileRecord& record, core::DiskImageReader& reader) = 0;
};

} // namespace filesystem
} // namespace forensivault
