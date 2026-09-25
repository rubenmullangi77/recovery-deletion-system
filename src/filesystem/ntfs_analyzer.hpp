#pragma once

#include "filesystem/fs_analyzer.hpp"
#include <string>
#include <vector>

namespace forensivault {
namespace filesystem {

class NTFSAnalyzer : public FilesystemAnalyzer {
public:
    NTFSAnalyzer();
    ~NTFSAnalyzer() override = default;

    bool probe(core::DiskImageReader& reader, uint64_t partitionStartSector = 0) override;
    FsVolumeInfo getVolumeInfo() const override;
    std::vector<FsFileRecord> listDirectory(const std::string& path = "/") override;
    std::vector<FsFileRecord> findDeletedFiles() override;
    std::vector<uint8_t> extractFile(const FsFileRecord& record, core::DiskImageReader& reader) override;
    uint64_t getActiveCount() const { return total_active_records_; }

private:
    FsVolumeInfo volume_info_;
    uint64_t partition_start_sector_{0};
    uint64_t mft_start_lcn_{0};
    uint32_t mft_record_size_{1024};
    uint64_t mft_byte_offset_{0};
    core::DiskImageReader* current_reader_{nullptr};

    std::vector<ClusterRun> mft_cluster_runs_;
    uint64_t mft_total_records_{0};
    uint64_t total_active_records_{0};
    bool mft_initialized_{false};

    void initMft(core::DiskImageReader& reader);
    void applyUsaFixup(uint8_t* recordData, size_t recordSize) const;
    std::vector<FsFileRecord> scanMftRecords(core::DiskImageReader& reader, bool lookForDeleted);
    bool parseMftRecord(const uint8_t* recordData, size_t recordSize, FsFileRecord& outRecord, bool& isAllocated);
    std::string parseUtf16LE(const uint8_t* bytes, size_t numChars) const;
    std::string formatFileTime(uint64_t filetime) const;
    std::vector<ClusterRun> parseRunlist(const uint8_t* runlistData, size_t maxLen) const;
};

} // namespace filesystem
} // namespace forensivault
