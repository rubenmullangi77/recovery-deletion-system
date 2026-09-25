#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace forensivault::core {

struct VolumeInfo {
    std::string drive_letter;     // e.g. "C:" or "D:"
    std::string volume_name;      // e.g. "Windows", "Data"
    std::string filesystem;       // e.g. "NTFS", "FAT32", "exFAT"
    std::string drive_type;       // e.g. "FIXED", "REMOVABLE", "CDROM"
    uint64_t total_bytes{0};
    uint64_t free_bytes{0};
    uint64_t used_bytes{0};
    bool is_system_drive{false};
    bool is_read_only{true};      // Forensic mode flag
    bool has_disk_extent{false};
    uint32_t disk_number{0};      // Physical disk number from IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS
    uint64_t starting_offset{0};
    uint64_t extent_length{0};
};

struct PhysicalPartitionInfo {
    uint32_t disk_number{0};
    uint32_t partition_number{0};
    std::string drive_letter;     // If mapped to volume (e.g. "C:")
    uint64_t starting_offset{0};
    uint64_t size_bytes{0};
    std::string partition_type;   // "Basic", "System", "Recovery", etc.
    std::string filesystem;       // Filesystem name if known
    std::string volume_label;     // Volume label if mapped
    bool is_boot{false};
    bool is_system{false};
};

struct PhysicalDiskInfo {
    uint32_t disk_number{0};
    std::string device_path;      // e.g. "\\\\.\\PhysicalDrive0"
    std::string friendly_name;    // e.g. "INTEL SSDPEKNU512GZH"
    std::string bus_type;         // e.g. "NVMe", "SATA", "USB"
    std::string manufacturer;     // e.g. "Intel", "SanDisk"
    std::string serial_number;    // Device serial number
    std::string partition_style;  // e.g. "GPT", "MBR"
    bool is_removable{false};
    uint64_t total_size_bytes{0};
    std::vector<PhysicalPartitionInfo> partitions;
};

struct StorageHierarchy {
    std::vector<PhysicalDiskInfo> physical_disks;
    std::vector<VolumeInfo> mounted_volumes;
    std::string detection_timestamp;
};

class StorageDeviceDetector {
public:
    static StorageHierarchy detectAllStorage();
    static std::string detectAllStorageJson();
};

} // namespace forensivault::core
