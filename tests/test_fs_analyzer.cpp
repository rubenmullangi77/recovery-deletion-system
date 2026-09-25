#include "test_framework.hpp"
#include "core/disk_image_reader.hpp"
#include "filesystem/fat32_analyzer.hpp"
#include "filesystem/exfat_analyzer.hpp"
#include "filesystem/ntfs_analyzer.hpp"
#include "recovery/recovery_engine.hpp"
#include "forensivault/common/crypto_hash.hpp"
#include <string>
#include <vector>
#include <fstream>
#include <algorithm>
#include <filesystem>

namespace fs = std::filesystem;

using namespace forensivault;
using namespace forensivault::core;
using namespace forensivault::filesystem;
using namespace forensivault::recovery;

namespace {

std::string computeFileHash(const std::string& path) {
    std::ifstream is(path, std::ios::binary);
    std::vector<uint8_t> d((std::istreambuf_iterator<char>(is)), std::istreambuf_iterator<char>());
    return CryptoHash::sha256(d);
}

} // anonymous namespace

FV_TEST(FilesystemAnalysis, FAT32VolumeProbeAndEnumeration) {
    std::string imgPath = "test_data/fat32_evidence.img";
    if (!fs::exists(imgPath)) {
        return;
    }
    std::string shaBefore = computeFileHash(imgPath);

    DiskImageReader reader(imgPath);
    ASSERT_TRUE(reader.isOpen());

    FAT32Analyzer fat32;
    ASSERT_TRUE(fat32.probe(reader, 0));

    auto vol = fat32.getVolumeInfo();
    ASSERT_TRUE(vol.valid);
    ASSERT_EQ(vol.fs_type, FsType::FAT32);
    ASSERT_EQ(vol.bytes_per_sector, 512U);
    ASSERT_EQ(vol.sectors_per_cluster, 8U);
    ASSERT_EQ(vol.cluster_size, 4096ULL);
    ASSERT_EQ(vol.volume_label, "FORENSIVLT");

    // Enumerate active files
    auto activeFiles = fat32.listDirectory("/");
    ASSERT_EQ(activeFiles.size(), 2ULL);

    auto itReadme = std::find_if(activeFiles.begin(), activeFiles.end(),
        [](const FsFileRecord& r) { return r.filename == "README.TXT"; });
    ASSERT_TRUE(itReadme != activeFiles.end());
    ASSERT_EQ(itReadme->allocation_status, AllocationStatus::ALLOCATED);
    ASSERT_EQ(itReadme->recovery_method, RecoveryMethod::FILESYSTEM_METADATA_ACTIVE);
    ASSERT_EQ(itReadme->starting_cluster, 3ULL);

    // Extract active file
    auto readmeData = fat32.extractFile(*itReadme, reader);
    ASSERT_TRUE(readmeData.size() > 0);
    std::string readmeStr(readmeData.begin(), readmeData.end());
    ASSERT_TRUE(readmeStr.find("ForensiVault FAT32 Active") != std::string::npos);

    // Enumerate deleted files
    auto deletedFiles = fat32.findDeletedFiles();
    ASSERT_EQ(deletedFiles.size(), 1ULL);
    const auto& delFile = deletedFiles[0];
    ASSERT_EQ(delFile.filename, "_ELETED.PNG");
    ASSERT_EQ(delFile.extension, "PNG");
    ASSERT_EQ(delFile.allocation_status, AllocationStatus::DELETED_CANDIDATE);
    ASSERT_EQ(delFile.recovery_method, RecoveryMethod::FILESYSTEM_METADATA_DELETED);
    ASSERT_EQ(delFile.starting_cluster, 5ULL);

    // Extract deleted PNG file
    auto pngData = fat32.extractFile(delFile, reader);
    ASSERT_TRUE(pngData.size() > 8);
    ASSERT_EQ(pngData[0], 0x89);
    ASSERT_EQ(pngData[1], 0x50); // 'P'
    ASSERT_EQ(pngData[2], 0x4E); // 'N'
    ASSERT_EQ(pngData[3], 0x47); // 'G'

    // Immutability check
    std::string shaAfter = computeFileHash(imgPath);
    ASSERT_EQ(shaBefore, shaAfter);
}

FV_TEST(FilesystemAnalysis, ExFATVolumeProbeAndMetadataRecovery) {
    std::string imgPath = "test_data/exfat_evidence.img";
    if (!fs::exists(imgPath)) {
        return;
    }
    std::string shaBefore = computeFileHash(imgPath);

    DiskImageReader reader(imgPath);
    ASSERT_TRUE(reader.isOpen());

    ExFATAnalyzer exfat;
    ASSERT_TRUE(exfat.probe(reader, 0));

    auto vol = exfat.getVolumeInfo();
    ASSERT_TRUE(vol.valid);
    ASSERT_EQ(vol.fs_type, FsType::EXFAT);
    ASSERT_EQ(vol.bytes_per_sector, 512U);
    ASSERT_EQ(vol.sectors_per_cluster, 8U);
    ASSERT_EQ(vol.cluster_size, 4096ULL);

    // Enumerate active files
    auto activeFiles = exfat.listDirectory("/");
    ASSERT_EQ(activeFiles.size(), 1ULL);
    ASSERT_EQ(activeFiles[0].filename, "REPORT.PDF");
    ASSERT_EQ(activeFiles[0].allocation_status, AllocationStatus::ALLOCATED);

    auto pdfData = exfat.extractFile(activeFiles[0], reader);
    ASSERT_TRUE(pdfData.size() > 5);
    std::string pdfHeader(pdfData.begin(), pdfData.begin() + 5);
    ASSERT_EQ(pdfHeader, "%PDF-");

    // Enumerate deleted candidates
    auto deletedFiles = exfat.findDeletedFiles();
    ASSERT_EQ(deletedFiles.size(), 1ULL);
    ASSERT_EQ(deletedFiles[0].filename, "SECRET.LOG");
    ASSERT_EQ(deletedFiles[0].allocation_status, AllocationStatus::DELETED_CANDIDATE);
    ASSERT_EQ(deletedFiles[0].recovery_method, RecoveryMethod::FILESYSTEM_METADATA_DELETED);

    auto logData = exfat.extractFile(deletedFiles[0], reader);
    std::string logStr(logData.begin(), logData.end());
    ASSERT_TRUE(logStr.find("CONFIDENTIAL INVESTIGATION") != std::string::npos);

    // Immutability check
    std::string shaAfter = computeFileHash(imgPath);
    ASSERT_EQ(shaBefore, shaAfter);
}

FV_TEST(FilesystemAnalysis, NTFSVolumeProbeAndMftRecovery) {
    std::string imgPath = "test_data/ntfs_evidence.img";
    if (!fs::exists(imgPath)) {
        return;
    }
    std::string shaBefore = computeFileHash(imgPath);

    DiskImageReader reader(imgPath);
    ASSERT_TRUE(reader.isOpen());

    NTFSAnalyzer ntfs;
    ASSERT_TRUE(ntfs.probe(reader, 0));

    auto vol = ntfs.getVolumeInfo();
    ASSERT_TRUE(vol.valid);
    ASSERT_EQ(vol.fs_type, FsType::NTFS);
    ASSERT_EQ(vol.bytes_per_sector, 512U);
    ASSERT_EQ(vol.sectors_per_cluster, 8U);
    ASSERT_EQ(vol.cluster_size, 4096ULL);

    // Enumerate active MFT records
    auto activeFiles = ntfs.listDirectory("/");
    auto itNotes = std::find_if(activeFiles.begin(), activeFiles.end(),
        [](const FsFileRecord& r) { return r.filename == "CASE_NOTES.TXT"; });
    ASSERT_TRUE(itNotes != activeFiles.end());
    ASSERT_EQ(itNotes->allocation_status, AllocationStatus::ALLOCATED);

    auto notesData = ntfs.extractFile(*itNotes, reader);
    std::string notesStr(notesData.begin(), notesData.end());
    ASSERT_TRUE(notesStr.find("ForensiVault NTFS Forensic Case Notes") != std::string::npos);

    // Enumerate deleted MFT records
    auto deletedFiles = ntfs.findDeletedFiles();
    auto itSuspect = std::find_if(deletedFiles.begin(), deletedFiles.end(),
        [](const FsFileRecord& r) { return r.filename == "SUSPECT.JPG"; });
    ASSERT_TRUE(itSuspect != deletedFiles.end());
    ASSERT_EQ(itSuspect->allocation_status, AllocationStatus::DELETED_CANDIDATE);
    ASSERT_EQ(itSuspect->recovery_method, RecoveryMethod::FILESYSTEM_METADATA_DELETED);

    auto jpegData = ntfs.extractFile(*itSuspect, reader);
    ASSERT_TRUE(jpegData.size() > 4);
    ASSERT_EQ(jpegData[0], 0xFF);
    ASSERT_EQ(jpegData[1], 0xD8);
    ASSERT_EQ(jpegData[2], 0xFF);
    ASSERT_EQ(jpegData[3], 0xE0);

    // Immutability check
    std::string shaAfter = computeFileHash(imgPath);
    ASSERT_EQ(shaBefore, shaAfter);
}

FV_TEST(RecoveryPipeline, DistinctFilesystemRecoveryVsCarvingFallback) {
    std::string imgPath = "test_data/fat32_evidence.img";
    if (!fs::exists(imgPath)) {
        return;
    }
    DiskImageReader reader(imgPath);
    ASSERT_TRUE(reader.isOpen());

    RecoveryEngine engine;
    auto report = engine.runRecovery(reader, "");

    ASSERT_TRUE(report.fs_detected);
    ASSERT_EQ(report.fs_type, FsType::FAT32);
    ASSERT_TRUE(report.filesystem_active_files.size() >= 1);
    ASSERT_TRUE(report.filesystem_deleted_files.size() >= 1);

    // Filesystem recovery preserves actual filenames
    bool foundDeletedPng = false;
    for (const auto& f : report.filesystem_deleted_files) {
        if (f.filename == "_ELETED.PNG") {
            foundDeletedPng = true;
            ASSERT_EQ(f.recovery_method, RecoveryMethod::FILESYSTEM_METADATA_DELETED);
            ASSERT_EQ(f.format_validation_status, "VALID");
            ASSERT_TRUE(f.confidence_score > 70); // Scored via RecoveryConfidenceScorer
            ASSERT_FALSE(f.sha256_hash.empty());
        }
    }
    ASSERT_TRUE(foundDeletedPng);

    // Test fallback on raw non-filesystem image (sample_disk.img)
    DiskImageReader rawReader("test_data/sample_disk.img");
    ASSERT_TRUE(rawReader.isOpen());

    auto rawReport = engine.runRecovery(rawReader, "");
    ASSERT_FALSE(rawReport.fs_detected);
    ASSERT_EQ(rawReport.fs_type, FsType::UNKNOWN);
    ASSERT_EQ(rawReport.filesystem_active_files.size(), 0ULL);
}
