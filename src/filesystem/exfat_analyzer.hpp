#pragma once

#include "filesystem/fs_analyzer.hpp"
#include <string>
#include <vector>

namespace forensivault {
namespace filesystem {

class ExFATAnalyzer : public FilesystemAnalyzer {
public:
    ExFATAnalyzer();
    ~ExFATAnalyzer() override = default;

    bool probe(core::DiskImageReader& reader, uint64_t partitionStartSector = 0) override;
    FsVolumeInfo getVolumeInfo() const override;
    std::vector<FsFileRecord> listDirectory(const std::string& path = "/") override;
    std::vector<FsFileRecord> findDeletedFiles() override;
    std::vector<uint8_t> extractFile(const FsFileRecord& record, core::DiskImageReader& reader) override;

private:
    FsVolumeInfo volume_info_;
    uint64_t partition_start_sector_{0};
    uint32_t cluster_heap_offset_sectors_{0};
    uint32_t root_cluster_{2};
    uint32_t cluster_count_{0};
    uint32_t fat_offset_sectors_{0};
    uint32_t fat_length_sectors_{0};
    core::DiskImageReader* current_reader_{nullptr};

    uint64_t clusterToByteOffset(uint32_t cluster) const;
    std::vector<FsFileRecord> parseDirectoryCluster(core::DiskImageReader& reader, uint32_t cluster, bool lookForDeleted);
    std::string parseUtf16LE(const uint8_t* bytes, size_t numChars) const;
};

} // namespace filesystem
} // namespace forensivault
