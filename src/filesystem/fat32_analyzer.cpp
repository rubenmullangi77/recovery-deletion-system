#include "filesystem/fat32_analyzer.hpp"
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
} // namespace

FAT32Analyzer::FAT32Analyzer() = default;

bool FAT32Analyzer::probe(core::DiskImageReader& reader, uint64_t partitionStartSector) {
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

    // Check boot signature 0x55AA
    if (bootSector[510] != 0x55 || bootSector[511] != 0xAA) {
        return false;
    }

    uint16_t bytesPerSec = readLE16(&bootSector[11]);
    uint8_t secPerClus = bootSector[13];
    uint16_t reservedSec = readLE16(&bootSector[14]);
    uint8_t numFats = bootSector[16];
    uint32_t secPerFat32 = readLE32(&bootSector[36]);
    uint32_t rootCluster = readLE32(&bootSector[44]);

    // Sanity checks for FAT32
    if (bytesPerSec != 512 && bytesPerSec != 1024 && bytesPerSec != 2048 && bytesPerSec != 4096) {
        return false;
    }
    if (secPerClus == 0 || (secPerClus & (secPerClus - 1)) != 0) {
        return false;
    }
    if (reservedSec == 0 || numFats == 0 || secPerFat32 == 0) {
        return false;
    }

    // Check if FS type string contains "FAT32" or total sectors matches FAT32 sizing
    char fsTypeStr[9] = {0};
    std::memcpy(fsTypeStr, &bootSector[82], 8);
    std::string fsType(fsTypeStr);
    bool hasFat32Sig = (fsType.find("FAT32") != std::string::npos);

    uint32_t totalSec32 = readLE32(&bootSector[32]);
    uint16_t totalSec16 = readLE16(&bootSector[19]);
    uint64_t totalSec = (totalSec32 != 0) ? totalSec32 : totalSec16;
    if (totalSec == 0 && reader.size() > 0) {
        totalSec = reader.size() / bytesPerSec;
    }

    uint64_t rootDirSectors = 0; // 0 on FAT32
    uint64_t dataSectors = totalSec - (reservedSec + (numFats * secPerFat32) + rootDirSectors);
    uint64_t totalClusters = dataSectors / secPerClus;

    if (!hasFat32Sig && totalClusters < 65525) {
        return false; // Not FAT32
    }

    // Populate volume info
    volume_info_.fs_type = FsType::FAT32;
    volume_info_.bytes_per_sector = bytesPerSec;
    volume_info_.sectors_per_cluster = secPerClus;
    volume_info_.cluster_size = static_cast<uint64_t>(bytesPerSec) * secPerClus;
    volume_info_.total_sectors = totalSec;
    volume_info_.total_clusters = totalClusters;
    volume_info_.partition_offset_bytes = offset;
    volume_info_.allocation_table_offset = offset + static_cast<uint64_t>(reservedSec) * bytesPerSec;
    volume_info_.valid = true;

    char label[12] = {0};
    std::memcpy(label, &bootSector[71], 11);
    volume_info_.volume_label = std::string(label);
    // Trim trailing spaces
    volume_info_.volume_label.erase(
        std::find_if(volume_info_.volume_label.rbegin(), volume_info_.volume_label.rend(),
                     [](unsigned char ch) { return !std::isspace(ch); }).base(),
        volume_info_.volume_label.end()
    );

    volume_info_.serial_number = readLE32(&bootSector[67]);

    reserved_sectors_ = reservedSec;
    num_fats_ = numFats;
    sectors_per_fat_ = secPerFat32;
    root_cluster_ = (rootCluster >= 2) ? rootCluster : 2;
    first_data_sector_ = reserved_sectors_ + (static_cast<uint64_t>(num_fats_) * sectors_per_fat_);

    volume_info_.root_dir_offset_bytes = clusterToByteOffset(root_cluster_);

    return true;
}

FsVolumeInfo FAT32Analyzer::getVolumeInfo() const {
    return volume_info_;
}

uint64_t FAT32Analyzer::clusterToSector(uint32_t cluster) const {
    if (cluster < 2) return partition_start_sector_ + first_data_sector_;
    return partition_start_sector_ + first_data_sector_ + (static_cast<uint64_t>(cluster - 2) * volume_info_.sectors_per_cluster);
}

uint64_t FAT32Analyzer::clusterToByteOffset(uint32_t cluster) const {
    return clusterToSector(cluster) * volume_info_.bytes_per_sector;
}

uint32_t FAT32Analyzer::getNextCluster(core::DiskImageReader& reader, uint32_t cluster) {
    if (cluster < 2 || sectors_per_fat_ == 0) {
        return 0x0FFFFFFF;
    }
    const uint64_t fatEntryOffset = volume_info_.allocation_table_offset + (static_cast<uint64_t>(cluster) * 4);
    if (fatEntryOffset + 4 > reader.size()) {
        return 0x0FFFFFFF;
    }
    uint8_t buf[4];
    if (!reader.read(fatEntryOffset, buf, 4)) {
        return 0x0FFFFFFF;
    }
    return readLE32(buf) & 0x0FFFFFFF;
}

std::string FAT32Analyzer::formatDosDateTime(uint16_t date, uint16_t time) const {
    int year = 1980 + ((date >> 9) & 0x7F);
    int month = (date >> 5) & 0x0F;
    int day = date & 0x1F;

    int hour = (time >> 11) & 0x1F;
    int min = (time >> 5) & 0x3F;
    int sec = (time & 0x1F) * 2;

    std::ostringstream oss;
    oss << std::setfill('0') << std::setw(4) << year << "-"
        << std::setw(2) << month << "-"
        << std::setw(2) << day << " "
        << std::setw(2) << hour << ":"
        << std::setw(2) << min << ":"
        << std::setw(2) << sec;
    return oss.str();
}

std::string FAT32Analyzer::format83Name(const uint8_t* raw, bool is_deleted) const {
    std::string base(reinterpret_cast<const char*>(raw), 8);
    std::string ext(reinterpret_cast<const char*>(raw + 8), 3);

    // If deleted, replace first character with placeholder
    if (is_deleted) {
        base[0] = '_';
    }

    // Trim trailing spaces
    while (!base.empty() && base.back() == ' ') base.pop_back();
    while (!ext.empty() && ext.back() == ' ') ext.pop_back();

    if (ext.empty()) {
        return base;
    }
    return base + "." + ext;
}

static std::string parseLfnChars(const uint8_t* entry) {
    std::string out;
    const size_t offsets[13] = {
        1, 3, 5, 7, 9,
        14, 16, 18, 20, 22, 24,
        28, 30
    };
    for (size_t off : offsets) {
        uint16_t c = static_cast<uint16_t>(entry[off]) | (static_cast<uint16_t>(entry[off + 1]) << 8);
        if (c == 0x0000 || c == 0xFFFF) break;
        if (c < 128) {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('?');
        }
    }
    return out;
}

std::vector<FsFileRecord> FAT32Analyzer::parseDirectoryCluster(core::DiskImageReader& reader, uint32_t cluster, bool lookForDeleted) {
    std::vector<FsFileRecord> results;
    if (cluster < 2) return results;

    const uint64_t clusterBytes = volume_info_.cluster_size;
    std::vector<uint8_t> clusterData(clusterBytes);
    std::vector<std::string> pendingLfnParts;

    uint32_t currClus = cluster;
    uint32_t loopGuard = 0;

    while (currClus >= 2 && currClus < 0x0FFFFFF8 && loopGuard++ < 1000) {
        uint64_t offset = clusterToByteOffset(currClus);
        if (offset + clusterBytes > reader.size()) {
            // Partial read if at end of image
            if (offset < reader.size()) {
                size_t toRead = static_cast<size_t>(reader.size() - offset);
                reader.read(offset, clusterData.data(), toRead);
                std::fill(clusterData.begin() + toRead, clusterData.end(), 0);
            } else {
                break;
            }
        } else {
            if (!reader.read(offset, clusterData.data(), clusterBytes)) {
                break;
            }
        }

        for (size_t i = 0; i + 32 <= clusterBytes; i += 32) {
            const uint8_t* entry = &clusterData[i];
            uint8_t firstByte = entry[0];

            if (firstByte == 0x00) {
                pendingLfnParts.clear();
                // End of directory entries
                if (!lookForDeleted) {
                    return results;
                }
                // When looking for deleted files, continue scanning rest of cluster
                continue;
            }

            uint8_t attr = entry[11];
            if (attr == 0x0F) {
                // Long file name entry
                std::string part = parseLfnChars(entry);
                if (!part.empty()) {
                    pendingLfnParts.insert(pendingLfnParts.begin(), part);
                }
                continue;
            }

            // Reconstruct LFN if available
            std::string reconstructedLfn;
            for (const auto& p : pendingLfnParts) {
                reconstructedLfn += p;
            }
            pendingLfnParts.clear();

            bool isDeleted = (firstByte == 0xE5);
            if (lookForDeleted != isDeleted) {
                continue;
            }

            // Skip '.' and '..' entries
            if (firstByte == 0x2E) {
                continue;
            }

            FsFileRecord rec;
            rec.attributes = attr;
            rec.is_directory = (attr & 0x10) != 0;

            if (!reconstructedLfn.empty()) {
                rec.filename = reconstructedLfn;
            } else {
                rec.filename = format83Name(entry, isDeleted);
            }
            
            // Extract extension
            size_t dotPos = rec.filename.rfind('.');
            if (dotPos != std::string::npos) {
                rec.extension = rec.filename.substr(dotPos + 1);
            }

            uint16_t clusHigh = readLE16(&entry[20]);
            uint16_t clusLow = readLE16(&entry[26]);
            rec.starting_cluster = (static_cast<uint32_t>(clusHigh) << 16) | clusLow;
            rec.file_size = readLE32(&entry[28]);
            rec.byte_offset = clusterToByteOffset(rec.starting_cluster);
            rec.full_path = "/" + rec.filename;

            uint16_t cDate = readLE16(&entry[16]);
            uint16_t cTime = readLE16(&entry[14]);
            rec.created_time = formatDosDateTime(cDate, cTime);

            uint16_t wDate = readLE16(&entry[24]);
            uint16_t wTime = readLE16(&entry[22]);
            rec.modified_time = formatDosDateTime(wDate, wTime);

            rec.allocation_status = isDeleted ? AllocationStatus::DELETED_CANDIDATE : AllocationStatus::ALLOCATED;
            rec.recovery_method = isDeleted ? RecoveryMethod::FILESYSTEM_METADATA_DELETED : RecoveryMethod::FILESYSTEM_METADATA_ACTIVE;

            // Compute cluster run and validate bounds
            if (rec.starting_cluster >= 2 && volume_info_.cluster_size > 0) {
                uint64_t numClustersNeeded = (rec.file_size + volume_info_.cluster_size - 1) / volume_info_.cluster_size;
                if (numClustersNeeded == 0 && rec.file_size > 0) numClustersNeeded = 1;

                uint64_t maxClus = volume_info_.total_clusters > 0 ? (2 + volume_info_.total_clusters) : 0xFFFFFF0ULL;
                if (rec.starting_cluster >= maxClus ||
                    (reader.size() > 0 && (rec.byte_offset > reader.size() || (reader.size() - rec.byte_offset) < rec.file_size))) {
                    rec.is_recoverable = false;
                    rec.unrecoverable_reason = "Cluster runs point beyond storage boundary.";
                    rec.allocation_status = AllocationStatus::NOT_RECOVERABLE;
                } else {
                    rec.cluster_runs.push_back({rec.starting_cluster, numClustersNeeded});
                    rec.fragment_count = 1;
                    rec.is_recoverable = true;
                    rec.allocation_status = isDeleted ? AllocationStatus::DELETED_CANDIDATE : AllocationStatus::ALLOCATED;
                }
            } else if (rec.file_size > 0) {
                rec.is_recoverable = false;
                rec.unrecoverable_reason = "Starting cluster is 0 or unavailable.";
                rec.allocation_status = AllocationStatus::NOT_RECOVERABLE;
            } else {
                rec.is_recoverable = true;
                rec.fragment_count = 0;
            }

            results.push_back(rec);
        }

        // Move to next cluster in chain for directory
        currClus = getNextCluster(reader, currClus);
    }

    return results;
}

std::vector<FsFileRecord> FAT32Analyzer::listDirectory(const std::string& /*path*/) {
    if (!current_reader_ || !volume_info_.valid) return {};
    return parseDirectoryCluster(*current_reader_, root_cluster_, false);
}

std::vector<FsFileRecord> FAT32Analyzer::findDeletedFiles() {
    if (!current_reader_ || !volume_info_.valid) return {};
    return parseDirectoryCluster(*current_reader_, root_cluster_, true);
}

std::vector<uint32_t> FAT32Analyzer::getClusterChain(core::DiskImageReader& reader, uint32_t start_cluster, uint64_t file_size) {
    std::vector<uint32_t> chain;
    if (start_cluster < 2) return chain;

    uint32_t curr = start_cluster;
    uint32_t loopGuard = 0;
    const uint64_t maxClusters = (file_size + volume_info_.cluster_size - 1) / volume_info_.cluster_size + 1;

    while (curr >= 2 && curr < 0x0FFFFFF8 && loopGuard++ < maxClusters && loopGuard < 100000) {
        chain.push_back(curr);
        uint32_t next = getNextCluster(reader, curr);
        if (next == 0 || next >= 0x0FFFFFF7) {
            // End of chain or zeroed (common in deleted files)
            break;
        }
        curr = next;
    }

    // If FAT table had 0 for deleted file, assume contiguous clusters up to file_size
    if (chain.size() < maxClusters && volume_info_.cluster_size > 0) {
        uint32_t needed = static_cast<uint32_t>((file_size + volume_info_.cluster_size - 1) / volume_info_.cluster_size);
        if (needed == 0 && file_size > 0) needed = 1;
        chain.clear();
        for (uint32_t c = 0; c < needed; ++c) {
            chain.push_back(start_cluster + c);
        }
    }

    return chain;
}

std::vector<uint8_t> FAT32Analyzer::extractFile(const FsFileRecord& record, core::DiskImageReader& reader) {
    std::vector<uint8_t> data;
    if (record.file_size == 0 || record.starting_cluster < 2) {
        return data;
    }

    data.resize(record.file_size);
    auto clusters = getClusterChain(reader, static_cast<uint32_t>(record.starting_cluster), record.file_size);

    uint64_t bytesRemaining = record.file_size;
    uint64_t bytesReadTotal = 0;

    for (uint32_t clus : clusters) {
        if (bytesRemaining == 0) break;
        uint64_t clusOffset = clusterToByteOffset(clus);
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
    }

    data.resize(bytesReadTotal);
    return data;
}

} // namespace filesystem
} // namespace forensivault
