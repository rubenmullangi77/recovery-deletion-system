#include "filesystem/exfat_analyzer.hpp"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace forensivault {
namespace filesystem {

namespace {
inline uint16_t readLE16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}

inline uint32_t readLE32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

inline uint64_t readLE64(const uint8_t* p) {
    return static_cast<uint64_t>(readLE32(p)) |
           (static_cast<uint64_t>(readLE32(p + 4)) << 32);
}
} // namespace

ExFATAnalyzer::ExFATAnalyzer() = default;

bool ExFATAnalyzer::probe(core::DiskImageReader& reader, uint64_t partitionStartSector) {
    partition_start_sector_ = partitionStartSector;
    current_reader_ = &reader;

    const uint64_t offset = partitionStartSector * 512;
    if (offset + 512 > reader.size()) {
        return false;
    }

    std::vector<uint8_t> bootSector(512);
    if (!reader.read(offset, bootSector.data(), 512)) {
        return false;
    }

    // Check boot signature 0x55AA at offset 510
    if (bootSector[510] != 0x55 || bootSector[511] != 0xAA) {
        return false;
    }

    // Check OEM Name: "EXFAT   "
    char oemName[9] = {0};
    std::memcpy(oemName, &bootSector[3], 8);
    if (std::strcmp(oemName, "EXFAT   ") != 0) {
        return false;
    }

    uint8_t bytesPerSecShift = bootSector[108]; // 0x6C
    uint8_t secPerClusShift = bootSector[109];  // 0x6D

    if (bytesPerSecShift < 9 || bytesPerSecShift > 12) { // 512 to 4096 bytes
        return false;
    }

    uint32_t bytesPerSec = 1U << bytesPerSecShift;
    uint32_t secPerClus = 1U << secPerClusShift;

    uint32_t clusterHeapOffset = readLE32(&bootSector[88]); // 0x58
    uint32_t clusterCount = readLE32(&bootSector[92]);      // 0x5C
    uint32_t rootCluster = readLE32(&bootSector[96]);       // 0x60
    uint32_t fatOffset = readLE32(&bootSector[80]);         // 0x50
    uint32_t fatLength = readLE32(&bootSector[84]);         // 0x54

    uint64_t volumeLengthSectors = readLE64(&bootSector[72]); // 0x48

    volume_info_.fs_type = FsType::EXFAT;
    volume_info_.bytes_per_sector = bytesPerSec;
    volume_info_.sectors_per_cluster = secPerClus;
    volume_info_.cluster_size = static_cast<uint64_t>(bytesPerSec) * secPerClus;
    volume_info_.total_sectors = volumeLengthSectors;
    volume_info_.total_clusters = clusterCount;
    volume_info_.partition_offset_bytes = offset;
    volume_info_.allocation_table_offset = offset + (static_cast<uint64_t>(fatOffset) * bytesPerSec);
    volume_info_.serial_number = readLE32(&bootSector[100]);
    volume_info_.volume_label = "exFAT_Volume";
    volume_info_.valid = true;

    cluster_heap_offset_sectors_ = clusterHeapOffset;
    root_cluster_ = (rootCluster >= 2) ? rootCluster : 2;
    cluster_count_ = clusterCount;
    fat_offset_sectors_ = fatOffset;
    fat_length_sectors_ = fatLength;

    volume_info_.root_dir_offset_bytes = clusterToByteOffset(root_cluster_);

    return true;
}

FsVolumeInfo ExFATAnalyzer::getVolumeInfo() const {
    return volume_info_;
}

uint64_t ExFATAnalyzer::clusterToByteOffset(uint32_t cluster) const {
    if (cluster < 2) return volume_info_.partition_offset_bytes + (static_cast<uint64_t>(cluster_heap_offset_sectors_) * volume_info_.bytes_per_sector);
    uint64_t clusterIndex = cluster - 2;
    uint64_t sectorOffset = cluster_heap_offset_sectors_ + (clusterIndex * volume_info_.sectors_per_cluster);
    return volume_info_.partition_offset_bytes + (sectorOffset * volume_info_.bytes_per_sector);
}

std::string ExFATAnalyzer::parseUtf16LE(const uint8_t* bytes, size_t numChars) const {
    std::string out;
    for (size_t i = 0; i < numChars; ++i) {
        uint16_t c = readLE16(bytes + (i * 2));
        if (c == 0) break;
        if (c < 128) {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('?');
        }
    }
    return out;
}

std::vector<FsFileRecord> ExFATAnalyzer::parseDirectoryCluster(core::DiskImageReader& reader, uint32_t cluster, bool lookForDeleted) {
    std::vector<FsFileRecord> results;
    if (cluster < 2) return results;

    const uint64_t clusterBytes = volume_info_.cluster_size;
    std::vector<uint8_t> clusterData(clusterBytes);

    uint64_t offset = clusterToByteOffset(cluster);
    if (offset + clusterBytes > reader.size()) {
        if (offset < reader.size()) {
            size_t toRead = static_cast<size_t>(reader.size() - offset);
            reader.read(offset, clusterData.data(), toRead);
            std::fill(clusterData.begin() + toRead, clusterData.end(), 0);
        } else {
            return results;
        }
    } else {
        if (!reader.read(offset, clusterData.data(), clusterBytes)) {
            return results;
        }
    }

    size_t i = 0;
    while (i + 32 <= clusterBytes) {
        const uint8_t* entry = &clusterData[i];
        uint8_t entryType = entry[0];

        if (entryType == 0x00) {
            // End of directory entries
            if (!lookForDeleted) {
                break;
            }
            i += 32;
            continue;
        }

        // Check if primary file directory entry (0x85 active, 0x05 deleted)
        bool isFileActive = (entryType == 0x85);
        bool isFileDeleted = (entryType == 0x05);

        if (!isFileActive && !isFileDeleted) {
            i += 32;
            continue;
        }

        if (lookForDeleted != isFileDeleted) {
            uint8_t secCount = entry[1];
            i += 32 * (1 + secCount);
            continue;
        }

        uint8_t secondaryCount = entry[1];
        uint16_t attributes = readLE16(&entry[4]);

        // Next entry should be Stream Extension (0xC0 active, 0x40 deleted)
        if (i + 32 * (1 + secondaryCount) > clusterBytes) {
            break;
        }

        const uint8_t* streamEntry = &clusterData[i + 32];
        uint8_t streamType = streamEntry[0];
        if (streamType != 0xC0 && streamType != 0x40) {
            i += 32;
            continue;
        }

        uint8_t nameLength = streamEntry[3];
        uint32_t firstCluster = readLE32(&streamEntry[20]);
        uint64_t dataLength = readLE64(&streamEntry[24]);

        // Remaining secondary entries are File Name entries (0xC1 active, 0x41 deleted)
        std::string fileName;
        for (uint8_t s = 1; s < secondaryCount; ++s) {
            const uint8_t* nameEntry = &clusterData[i + 32 * (1 + s)];
            uint8_t nType = nameEntry[0];
            if (nType != 0xC1 && nType != 0x41) {
                continue;
            }
            fileName += parseUtf16LE(&nameEntry[2], 15);
        }

        if (fileName.length() > nameLength) {
            fileName = fileName.substr(0, nameLength);
        }

        FsFileRecord rec;
        rec.filename = fileName;
        rec.file_size = dataLength;
        rec.starting_cluster = firstCluster;
        rec.byte_offset = clusterToByteOffset(firstCluster);
        rec.attributes = attributes;
        rec.is_directory = (attributes & 0x10) != 0;
        rec.full_path = "/" + fileName;

        size_t dotPos = rec.filename.rfind('.');
        if (dotPos != std::string::npos) {
            rec.extension = rec.filename.substr(dotPos + 1);
        }

        rec.allocation_status = isFileDeleted ? AllocationStatus::DELETED_CANDIDATE : AllocationStatus::ALLOCATED;
        rec.recovery_method = isFileDeleted ? RecoveryMethod::FILESYSTEM_METADATA_DELETED : RecoveryMethod::FILESYSTEM_METADATA_ACTIVE;

        if (firstCluster >= 2 && volume_info_.cluster_size > 0) {
            uint64_t numClusters = (dataLength + volume_info_.cluster_size - 1) / volume_info_.cluster_size;
            if (numClusters == 0 && dataLength > 0) numClusters = 1;
            rec.cluster_runs.push_back({firstCluster, numClusters});
            rec.fragment_count = 1;
            rec.is_recoverable = true;
        } else if (dataLength > 0) {
            rec.is_recoverable = false;
            rec.unrecoverable_reason = "exFAT starting cluster unavailable or outside cluster heap.";
            rec.allocation_status = AllocationStatus::NOT_RECOVERABLE;
        } else {
            rec.is_recoverable = true;
            rec.fragment_count = 0;
        }

        results.push_back(rec);
        i += 32 * (1 + secondaryCount);
    }

    return results;
}

std::vector<FsFileRecord> ExFATAnalyzer::listDirectory(const std::string& /*path*/) {
    if (!current_reader_ || !volume_info_.valid) return {};
    return parseDirectoryCluster(*current_reader_, root_cluster_, false);
}

std::vector<FsFileRecord> ExFATAnalyzer::findDeletedFiles() {
    if (!current_reader_ || !volume_info_.valid) return {};
    return parseDirectoryCluster(*current_reader_, root_cluster_, true);
}

std::vector<uint8_t> ExFATAnalyzer::extractFile(const FsFileRecord& record, core::DiskImageReader& reader) {
    std::vector<uint8_t> data;
    if (record.file_size == 0 || record.starting_cluster < 2) {
        return data;
    }

    data.resize(record.file_size);
    uint64_t bytesRemaining = record.file_size;
    uint64_t bytesReadTotal = 0;
    uint32_t currCluster = static_cast<uint32_t>(record.starting_cluster);

    while (bytesRemaining > 0 && currCluster < (2 + cluster_count_)) {
        uint64_t clusOffset = clusterToByteOffset(currCluster);
        uint64_t toRead = std::min(bytesRemaining, volume_info_.cluster_size);

        if (clusOffset + toRead > reader.size()) {
            if (clusOffset < reader.size()) {
                toRead = reader.size() - clusOffset;
            } else {
                break;
            }
        }

        if (!reader.read(clusOffset, data.data() + bytesReadTotal, toRead)) {
            break;
        }

        bytesReadTotal += toRead;
        bytesRemaining -= toRead;
        currCluster++; // For contiguous / NoFatChain files
    }

    data.resize(bytesReadTotal);
    return data;
}

} // namespace filesystem
} // namespace forensivault
