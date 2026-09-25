#include "core/disk_image_reader.hpp"
#include "core/binary_utils.hpp"
#include "recovery/recovery_engine.hpp"
#include "forensivault/common/logger.hpp"

#include <string>
#include <vector>
#include <iomanip>
#include <sstream>

using namespace forensivault;
using namespace forensivault::core;
using namespace forensivault::recovery;

namespace {

void printUsage() {
    FV_PRINTLN("Usage: forensic-inspect <disk_image> [options]");
    FV_PRINTLN("");
    FV_PRINTLN("Options:");
    FV_PRINTLN("  -b, --binary        Display bitwise binary representation of sector 0");
    FV_PRINTLN("  -f, --fs            Analyze and display filesystem volume details");
    FV_PRINTLN("  -s, --sector <N>    Read and dump sector N (default: 0)");
    FV_PRINTLN("  --search <HEX>      Search for raw byte sequence (e.g. 504B0304 for ZIP)");
    FV_PRINTLN("  -h, --help          Show this forensic inspection help reference");
    FV_PRINTLN("");
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage();
        return 1;
    }

    std::string imagePath;
    bool showBinary = false;
    bool analyzeFs = false;
    uint64_t targetSector = 0;
    std::string searchHex;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            printUsage();
            return 0;
        } else if (arg == "--binary" || arg == "-b") {
            showBinary = true;
        } else if (arg == "--fs" || arg == "-f") {
            analyzeFs = true;
        } else if ((arg == "--sector" || arg == "-s") && i + 1 < argc) {
            targetSector = std::stoull(argv[++i]);
        } else if (arg == "--search" && i + 1 < argc) {
            searchHex = argv[++i];
        } else if (imagePath.empty() && arg[0] != '-') {
            imagePath = arg;
        }
    }

    if (imagePath.empty()) {
        FV_PRINTERRLN("[ERROR] No image file specified.");
        printUsage();
        return 1;
    }

    // Open image in strictly READ-ONLY mode
    DiskImageReader reader(imagePath);
    if (!reader.isOpen()) {
        FV_PRINTERRLN("[ERROR] Could not open disk image: " + reader.lastError());
        return 1;
    }

    // Display image metadata
    FV_PRINTLN("============================================================");
    FV_PRINTLN("           ForensiVault Image Inspection Tool               ");
    FV_PRINTLN("============================================================");
    FV_PRINTLN("Image Path:    " + reader.filepath());
    {
        std::ostringstream ss;
        ss << "Image Size:    " << reader.size() << " bytes ("
           << std::fixed << std::setprecision(2)
           << (static_cast<double>(reader.size()) / (1024.0 * 1024.0)) << " MB)";
        FV_PRINTLN(ss.str());
    }
    FV_PRINTLN("Total Sectors: " + std::to_string(reader.totalSectors()) + " sectors");
    FV_PRINTLN("Sector Size:   " + std::to_string(reader.sectorSize()) + " bytes");
    FV_PRINTLN("============================================================\n");

    if (analyzeFs) {
        FV_PRINTLN("[FILESYSTEM ANALYSIS]");
        RecoveryEngine engine;
        auto analyzer = engine.detectFilesystem(reader, 0);
        if (!analyzer) {
            FV_PRINTLN("No supported filesystem (FAT32, exFAT, NTFS) detected at sector 0.\n");
        } else {
            auto vol = analyzer->getVolumeInfo();
            std::ostringstream fsSs;
            fsSs << vol.fs_type;
            FV_PRINTLN("Detected FS:       " + fsSs.str());
            FV_PRINTLN("Volume Label:      " + (vol.volume_label.empty() ? "(None)" : vol.volume_label));
            {
                std::ostringstream ss;
                ss << "Serial Number:     0x" << std::hex << std::uppercase << vol.serial_number;
                FV_PRINTLN(ss.str());
            }
            FV_PRINTLN("Bytes Per Sector:  " + std::to_string(vol.bytes_per_sector) + " bytes");
            FV_PRINTLN("Sectors / Cluster: " + std::to_string(vol.sectors_per_cluster));
            FV_PRINTLN("Cluster Size:      " + std::to_string(vol.cluster_size) + " bytes");
            FV_PRINTLN("Total Sectors:     " + std::to_string(vol.total_sectors));
            {
                std::ostringstream ss;
                ss << "Table Offset:      0x" << std::hex << vol.allocation_table_offset << "\n";
                FV_PRINTLN(ss.str());
            }

            FV_PRINTLN("--- Active Files (Filesystem Recovery) ---");
            auto activeFiles = analyzer->listDirectory("/");
            if (activeFiles.empty()) {
                FV_PRINTLN("  (No active files found)");
            } else {
                for (const auto& f : activeFiles) {
                    std::ostringstream ss;
                    ss << "  [ACTIVE] " << std::left << std::setw(16) << f.filename
                       << " Size: " << std::right << std::setw(8) << f.file_size << " bytes"
                       << " Offset: 0x" << std::hex << f.byte_offset << std::dec
                       << " Cluster: " << f.starting_cluster;
                    FV_PRINTLN(ss.str());
                }
            }
            FV_PRINTLN();

            FV_PRINTLN("--- Deleted-File Candidates (Filesystem Tombstones) ---");
            auto deletedFiles = analyzer->findDeletedFiles();
            if (deletedFiles.empty()) {
                FV_PRINTLN("  (No deleted-file candidates found)");
            } else {
                for (const auto& f : deletedFiles) {
                    std::ostringstream ss;
                    ss << "  [DELETED CANDIDATE] " << std::left << std::setw(16) << f.filename
                       << " Size: " << std::right << std::setw(8) << f.file_size << " bytes"
                       << " Offset: 0x" << std::hex << f.byte_offset << std::dec
                       << " Cluster: " << f.starting_cluster;
                    FV_PRINTLN(ss.str());
                }
            }
            FV_PRINTLN();
        }
    }

    // If search was requested
    if (!searchHex.empty()) {
        std::vector<uint8_t> needle = BinaryUtils::fromHex(searchHex);
        if (needle.empty()) {
            FV_PRINTERRLN("[ERROR] Invalid hex sequence for search: " + searchHex);
        } else {
            FV_PRINTLN("[SEARCH] Searching for sequence: " + BinaryUtils::toHex(needle) + " (" + std::to_string(needle.size()) + " bytes)");
            
            // Stream search through image
            std::vector<uint8_t> chunk(64 * 1024);
            uint64_t currentOffset = 0;
            size_t matchCount = 0;

            while (currentOffset < reader.size() && matchCount < 20) {
                size_t toRead = static_cast<size_t>(std::min<uint64_t>(chunk.size(), reader.size() - currentOffset));
                if (!reader.read(currentOffset, chunk.data(), toRead)) break;

                auto matches = BinaryUtils::findAll(chunk.data(), toRead, needle.data(), needle.size());
                for (uint64_t m : matches) {
                    uint64_t absOffset = currentOffset + m;
                    uint64_t sector = BinaryUtils::byteToSector(absOffset, reader.sectorSize());
                    uint32_t rem = BinaryUtils::offsetWithinSector(absOffset, reader.sectorSize());
                    std::ostringstream ss;
                    ss << "  Match #" << (++matchCount) << " found at offset 0x" 
                       << std::hex << std::uppercase << absOffset 
                       << " (Sector " << std::dec << sector << " + " << rem << " bytes)";
                    FV_PRINTLN(ss.str());
                    if (matchCount >= 20) break;
                }
                
                if (toRead <= needle.size()) break;
                currentOffset += (toRead - needle.size() + 1);
            }

            FV_PRINTLN("Search complete. Total matches reported: " + std::to_string(matchCount) + "\n");
        }
    }

    // Read target sector (default sector 0)
    FV_PRINTLN("[SECTOR DUMP: Sector " + std::to_string(targetSector) + " (512 bytes)]");
    std::vector<uint8_t> sectorData = reader.readSector(targetSector);
    if (sectorData.empty()) {
        FV_PRINTERRLN("[ERROR] Failed to read sector " + std::to_string(targetSector) + ": " + reader.lastError());
        return 1;
    }

    // SHA-256 of the inspected sector
    std::string sectorSha = BinaryUtils::sha256(sectorData);
    FV_PRINTLN("SHA-256 (Sector " + std::to_string(targetSector) + "): " + sectorSha + "\n");

    // Formatted hex dump
    uint64_t baseOffset = BinaryUtils::sectorToByteOffset(targetSector, reader.sectorSize());
    std::string hexDump = BinaryUtils::formatHexDump(sectorData, baseOffset, 16);
    FV_PRINTLN(hexDump);

    // If binary bitwise representation was requested
    if (showBinary) {
        FV_PRINTLN("[BITWISE BINARY REPRESENTATION (First 32 bytes)]");
        size_t binCount = std::min<size_t>(32, sectorData.size());
        for (size_t i = 0; i < binCount; ++i) {
            std::ostringstream ss;
            ss << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(4) << (baseOffset + i)
               << "  [0x" << BinaryUtils::byteToHex(sectorData[i]) << "]  "
               << BinaryUtils::byteToBinary(sectorData[i]) << "  '"
               << BinaryUtils::toAscii(sectorData[i]) << "'";
            FV_PRINTLN(ss.str());
        }
        FV_PRINTLN();
    }

    return 0;
}
