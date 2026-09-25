#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "core/disk_image_reader.hpp"

namespace forensivault::core {

enum class PartitionTableType {
    NONE = 0,
    MBR,
    GPT,
    RAW_SUPERFLOPPY
};

struct PartitionEntry {
    uint32_t partition_number{0};
    uint64_t start_sector{0};
    uint64_t sector_count{0};
    uint64_t size_bytes{0};
    uint8_t partition_type_id{0};
    std::string type_name;
    std::string type_guid;
    std::string partition_name;
    bool is_bootable{false};
    std::string size_formatted;
};

struct DiskPartitionMap {
    PartitionTableType table_type{PartitionTableType::NONE};
    std::string table_type_str{"NONE"};
    uint64_t total_disk_sectors{0};
    uint32_t sector_size{512};
    std::vector<PartitionEntry> partitions; 
};

class PartitionDetector {
public:
    static DiskPartitionMap detectPartitions(DiskImageReader& reader);
    static std::string formatPartitionSize(uint64_t bytes);
    static std::string getMbrTypeName(uint8_t typeId);
    static std::string getGptTypeName(const std::string& guid);
};

} // namespace forensivault::core
