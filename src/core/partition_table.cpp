#include "core/partition_table.hpp"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace forensivault::core {

namespace {
inline uint16_t readLE16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}
inline uint32_t readLE32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}
inline uint64_t readLE64(const uint8_t* p) {
    return static_cast<uint64_t>(readLE32(p)) | (static_cast<uint64_t>(readLE32(p + 4)) << 32);
}
} // namespace

std::string PartitionDetector::formatPartitionSize(uint64_t bytes) {
    const double KB = 1024.0;
    const double MB = KB * 1024.0;
    const double GB = MB * 1024.0;
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(2);
    if (bytes >= GB) {
        ss << (bytes / GB) << " GB";
    } else if (bytes >= MB) {
        ss << (bytes / MB) << " MB";
    } else if (bytes >= KB) {
        ss << (bytes / KB) << " KB";
    } else {
        ss << bytes << " B";
    }
    return ss.str();
}

std::string PartitionDetector::getMbrTypeName(uint8_t typeId) {
    switch (typeId) {
        case 0x01: return "FAT12";
        case 0x04: return "FAT16 (<32MB)";
        case 0x06: return "FAT16";
        case 0x07: return "NTFS / exFAT";
        case 0x0B: return "FAT32 (CHS)";
        case 0x0C: return "FAT32 (LBA)";
        case 0x0E: return "FAT16 (LBA)";
        case 0x0F: return "Extended (LBA)";
        case 0x82: return "Linux Swap";
        case 0x83: return "Linux Native (ext2/3/4)";
        case 0xEE: return "GPT Protective MBR";
        case 0xEF: return "EFI System Partition";
        default: {
            std::ostringstream oss;
            oss << "Unknown (0x" << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << static_cast<int>(typeId) << ")";
            return oss.str();
        }
    }
}

std::string PartitionDetector::getGptTypeName(const std::string& guid) {
    std::string upperGuid = guid;
    std::transform(upperGuid.begin(), upperGuid.end(), upperGuid.begin(), ::toupper);
    if (upperGuid == "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7") {
        return "Microsoft Basic Data (NTFS/FAT32/exFAT)";
    } else if (upperGuid == "C12A7328-F81F-11D2-BA4B-00A0C93EC93B") {
        return "EFI System Partition";
    } else if (upperGuid == "0FC63DAF-8483-4772-8E79-3D69D8477DE4") {
        return "Linux Filesystem Data";
    } else if (upperGuid == "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC") {
        return "Windows Recovery Environment";
    }
    return "GPT Data Partition";
}

DiskPartitionMap PartitionDetector::detectPartitions(DiskImageReader& reader) {
    DiskPartitionMap result;
    result.total_disk_sectors = reader.totalSectors();
    result.sector_size = reader.sectorSize();

    if (reader.size() < 512) {
        return result;
    }

    std::vector<uint8_t> sector0(512);
    if (!reader.read(0, sector0.data(), 512)) {
        return result;
    }

    // Check for 0x55AA signature at offset 510
    bool hasBootSig = (sector0[510] == 0x55 && sector0[511] == 0xAA);

    // Check GPT: Look at LBA 1 for "EFI PART"
    if (reader.size() >= 1024) {
        std::vector<uint8_t> sector1(512);
        if (reader.read(512, sector1.data(), 512)) {
            if (std::memcmp(sector1.data(), "EFI PART", 8) == 0) {
                result.table_type = PartitionTableType::GPT;
                result.table_type_str = "GPT";

                uint64_t partitionEntryLba = readLE64(&sector1[72]);
                uint32_t numEntries = readLE32(&sector1[80]);
                uint32_t entrySize = readLE32(&sector1[84]);

                if (entrySize >= 128 && numEntries > 0 && numEntries <= 256) {
                    size_t tableBytes = static_cast<size_t>(numEntries) * entrySize;
                    std::vector<uint8_t> tableBuf(tableBytes);
                    if (reader.read(partitionEntryLba * 512, tableBuf.data(), tableBytes)) {
                        uint32_t pIndex = 1;
                        for (uint32_t i = 0; i < numEntries; ++i) {
                            const uint8_t* entry = &tableBuf[i * entrySize];
                            bool isZeroType = true;
                            for (int b = 0; b < 16; ++b) {
                                if (entry[b] != 0) { isZeroType = false; break; }
                            }
                            if (isZeroType) continue;

                            uint64_t firstLba = readLE64(&entry[32]);
                            uint64_t lastLba = readLE64(&entry[40]);
                            if (firstLba > lastLba || firstLba >= reader.totalSectors()) continue;

                            uint64_t sectorCount = lastLba - firstLba + 1;
                            uint64_t sizeBytes = sectorCount * 512;

                            char guidStr[40] = {0};
                            std::snprintf(guidStr, sizeof(guidStr),
                                "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                                entry[3], entry[2], entry[1], entry[0],
                                entry[5], entry[4], entry[7], entry[6],
                                entry[8], entry[9], entry[10], entry[11], entry[12], entry[13], entry[14], entry[15]);

                            std::string partName;
                            for (int c = 0; c < 36; ++c) {
                                uint16_t ch = readLE16(&entry[56 + c * 2]);
                                if (ch == 0) break;
                                if (ch < 128) partName.push_back(static_cast<char>(ch));
                            }

                            PartitionEntry pe;
                            pe.partition_number = pIndex++;
                            pe.start_sector = firstLba;
                            pe.sector_count = sectorCount;
                            pe.size_bytes = sizeBytes;
                            pe.type_guid = guidStr;
                            pe.type_name = getGptTypeName(guidStr);
                            pe.partition_name = partName;
                            pe.is_bootable = false;
                            pe.size_formatted = formatPartitionSize(sizeBytes);

                            result.partitions.push_back(pe);
                        }
                    }
                }
                if (!result.partitions.empty()) {
                    return result;
                }
            }
        }
    }

    // Check MBR partition table entries at offset 446..509 (4 entries of 16 bytes each)
    if (hasBootSig) {
        bool isProtectiveGpt = false;
        std::vector<PartitionEntry> mbrEntries;
        uint32_t pNum = 1;

        for (int i = 0; i < 4; ++i) {
            const uint8_t* pEntry = &sector0[446 + i * 16];
            uint8_t bootFlag = pEntry[0];
            uint8_t typeId = pEntry[4];
            uint32_t lbaStart = readLE32(&pEntry[8]);
            uint32_t lbaCount = readLE32(&pEntry[12]);

            if (typeId == 0xEE) {
                isProtectiveGpt = true;
            }

            if (typeId != 0 && lbaCount > 0 && lbaStart < reader.totalSectors()) {
                PartitionEntry pe;
                pe.partition_number = pNum++;
                pe.start_sector = lbaStart;
                pe.sector_count = lbaCount;
                pe.size_bytes = static_cast<uint64_t>(lbaCount) * 512;
                pe.partition_type_id = typeId;
                pe.type_name = getMbrTypeName(typeId);
                pe.is_bootable = (bootFlag == 0x80);
                pe.size_formatted = formatPartitionSize(pe.size_bytes);
                mbrEntries.push_back(pe);
            }
        }

        if (!isProtectiveGpt && !mbrEntries.empty()) {
            result.table_type = PartitionTableType::MBR;
            result.table_type_str = "MBR";
            result.partitions = std::move(mbrEntries);
            return result;
        }
    }

    // Fallback: Superfloppy / Raw Filesystem Volume directly on disk (Partition 0 at LBA 0)
    result.table_type = PartitionTableType::RAW_SUPERFLOPPY;
    result.table_type_str = "RAW_VOLUME";

    PartitionEntry single;
    single.partition_number = 1;
    single.start_sector = 0;
    single.sector_count = reader.totalSectors();
    single.size_bytes = reader.size();
    single.type_name = "Direct Volume / Superfloppy";
    single.is_bootable = hasBootSig;
    single.size_formatted = formatPartitionSize(reader.size());
    result.partitions.push_back(single);

    return result;
}

} // namespace forensivault::core
