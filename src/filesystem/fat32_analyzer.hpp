#pragma once

#include "filesystem/fs_analyzer.hpp"
#include <string>
#include <vector>

namespace forensivault {
namespace filesystem {

class FAT32Analyzer : public FilesystemAnalyzer {
public:
    FAT32Analyzer();
    ~FAT32Analyzer() override = default;

    bool probe(core::DiskImageReader& reader, uint64_t partitionStartSector = 0) override;
    FsVolumeInfo getVolumeInfo() const override;
    std::vector<FsFileRecord> listDirectory(const std::string& path = "/") override;
    std::vector<FsFileRecord> findDeletedFiles() override;
    std::vector<uint8_t> extractFile(const FsFileRecord& record, core::DiskImageReader& reader) override;

private:
    struct DirectoryEntryRaw {
        uint8_t name[11];
        uint8_t attributes;
        uint8_t nt_reserved;
        uint8_t create_time_tenth;
        uint16_t create_time;
        uint16_t create_date;
        uint16_t access_date;
        uint16_t cluster_high;
        uint16_t write_time;
        uint16_t write_date;
        uint16_t cluster_low;
        uint32_t file_size;
    };

    FsVolumeInfo volume_info_;
    uint64_t partition_start_sector_{0};
    uint16_t reserved_sectors_{0};
    uint8_t num_fats_{0};
    uint32_t sectors_per_fat_{0};
    uint32_t root_cluster_{2};
    uint64_t first_data_sector_{0};
    core::DiskImageReader* current_reader_{nullptr};

    uint64_t clusterToSector(uint32_t cluster) const;
    uint64_t clusterToByteOffset(uint32_t cluster) const;
    uint32_t getNextCluster(core::DiskImageReader& reader, uint32_t cluster);
    std::vector<uint32_t> getClusterChain(core::DiskImageReader& reader, uint32_t start_cluster, uint64_t file_size);
    std::vector<FsFileRecord> parseDirectoryCluster(core::DiskImageReader& reader, uint32_t cluster, bool lookForDeleted);
    std::string formatDosDateTime(uint16_t date, uint16_t time) const;
    std::string format83Name(const uint8_t* name_raw, bool is_deleted) const;
};

} // namespace filesystem
} // namespace forensivault
