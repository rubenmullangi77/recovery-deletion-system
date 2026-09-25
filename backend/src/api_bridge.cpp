#include "forensivault/forensivault.hpp"
#include "sanitization/secure_file_eraser.hpp"
#include "sanitization/secure_folder_eraser.hpp"
#include "sanitization/system_protection.hpp"
#include "sanitization/drive_detector.hpp"
#include "sanitization/image_sanitizer.hpp"
#include "sanitization/sanitization_strategy.hpp"
#include "carving/file_carver.hpp"
#include "core/disk_image_reader.hpp"
#include "filesystem/fat32_analyzer.hpp"
#include "filesystem/exfat_analyzer.hpp"
#include "filesystem/ntfs_analyzer.hpp"
#include "recovery/recovery_engine.hpp"

#include <chrono>
#include <filesystem>
#include <iostream>
#include <memory>

namespace fs = std::filesystem;

namespace forensivault::api {

// ============================================================================
// FileEraserAPI Implementation
// ============================================================================

ErasePreviewReport FileEraserAPI::preview(const std::string& targetPath) {
    ErasePreviewReport report;

    // Check system protection
    if (core::Platform::isRootOrSystemPath(targetPath)) {
        report.isRootOrSystemProtected = true;
        report.protectionReason = "Path is protected OS root or critical system directory. Destruction strictly prohibited.";
        return report;
    }

    std::error_code ec;
    if (!fs::exists(targetPath, ec)) {
        report.protectionReason = "Specified path does not exist.";
        return report;
    }

    if (fs::is_directory(targetPath, ec)) {
        for (const auto& entry : fs::recursive_directory_iterator(targetPath, fs::directory_options::skip_permission_denied, ec)) {
            ErasePreviewItem item;
            item.path = entry.path().string();
            item.isDirectory = entry.is_directory(ec);
            if (!item.isDirectory) {
                item.sizeBytes = entry.file_size(ec);
                report.totalFiles++;
                report.totalBytes += item.sizeBytes;
            } else {
                report.totalDirectories++;
            }
            report.items.push_back(std::move(item));
        }
    } else {
        ErasePreviewItem item;
        item.path = targetPath;
        item.isDirectory = false;
        item.sizeBytes = fs::file_size(targetPath, ec);
        report.totalFiles = 1;
        report.totalBytes = item.sizeBytes;
        report.items.push_back(std::move(item));
    }

    return report;
}

EraseResult FileEraserAPI::eraseFile(const std::string& filePath,
                                     EraseMethod method,
                                     EraseProgressCallback cb) {
    EraseResult result;
    result.targetPath = filePath;

    if (core::Platform::isRootOrSystemPath(filePath) || core::Platform::isMainSystemDrive(filePath)) {
        result.errorMessage = "Refusing to erase protected system, /root, or root path: " + filePath + " (Protected even with root / admin privileges).";
        return result;
    }

    sanitization::SanitizationMethod sm;
    switch (method) {
        case EraseMethod::DOD_5220_22_M:
            sm = sanitization::SanitizationMethod::DOD_5220_22_M;
            break;
        case EraseMethod::PSEUDO_RANDOM:
            sm = sanitization::SanitizationMethod::PSEUDORANDOM_1_PASS;
            break;
        case EraseMethod::NIST_800_88_CLEAR:
        default:
            sm = sanitization::SanitizationMethod::NIST_800_88_CLEAR;
            break;
    }

    std::error_code ec;
    uint64_t fsize = fs::exists(filePath, ec) ? fs::file_size(filePath, ec) : 0;

    sanitization::SecureFileEraser eraser;
    sanitization::VerificationResult vr = eraser.eraseFile(filePath, sm, [cb, filePath](const sanitization::EraseProgress& p) {
        if (cb) {
            EraseProgress ep;
            ep.currentPath = filePath;
            ep.bytesProcessed = p.bytes_processed_file;
            ep.totalBytes = p.file_size_bytes;
            ep.percentComplete = p.percentage;
            ep.currentPass = p.current_pass;
            ep.totalPasses = p.total_passes;
            cb(ep);
        }
    });

    result.success = vr.is_verified && !vr.accessible_after_deletion;
    result.bytesErased = fsize;
    result.filesErased = result.success ? 1 : 0;
    result.passesCompleted = sanitization::SecureFileEraser::getPassCount(sm);
    result.verificationPassed = vr.is_verified;
    result.auditSignature = vr.details;
    if (!result.success) {
        result.errorMessage = vr.details;
    }

    return result;
}

EraseResult FileEraserAPI::eraseDirectory(const std::string& dirPath,
                                          EraseMethod method,
                                          EraseProgressCallback cb) {
    EraseResult result;
    result.targetPath = dirPath;

    if (core::Platform::isRootOrSystemPath(dirPath) || core::Platform::isMainSystemDrive(dirPath)) {
        result.errorMessage = "Refusing to erase protected system, /root, or root directory: " + dirPath + " (Protected even with root / admin privileges).";
        return result;
    }

    sanitization::SanitizationMethod sm;
    switch (method) {
        case EraseMethod::DOD_5220_22_M:
            sm = sanitization::SanitizationMethod::DOD_5220_22_M;
            break;
        case EraseMethod::PSEUDO_RANDOM:
            sm = sanitization::SanitizationMethod::PSEUDORANDOM_1_PASS;
            break;
        case EraseMethod::NIST_800_88_CLEAR:
        default:
            sm = sanitization::SanitizationMethod::NIST_800_88_CLEAR;
            break;
    }

    sanitization::SecureFolderEraser eraser;
    sanitization::FolderEraseReport fr = eraser.eraseFolder(dirPath, sm, [cb](const sanitization::EraseProgress& p) {
        if (cb) {
            EraseProgress ep;
            ep.currentPath = p.current_file;
            ep.bytesProcessed = p.total_bytes_processed;
            ep.totalBytes = p.total_bytes_all;
            ep.percentComplete = p.percentage;
            ep.currentPass = p.current_pass;
            ep.totalPasses = p.total_passes;
            cb(ep);
        }
    });

    result.success = fr.success;
    result.filesErased = fr.files_erased;
    result.directoriesErased = fr.folders_removed;
    result.bytesErased = fr.total_bytes_erased;
    result.passesCompleted = sanitization::SecureFileEraser::getPassCount(sm);
    result.verificationPassed = fr.success;
    result.auditSignature = fr.details;
    if (!fr.success) {
        result.errorMessage = fr.details;
    }

    return result;
}

// ============================================================================
// DriveSanitizerAPI Implementation
// ============================================================================

std::vector<StorageDeviceDescriptor> DriveSanitizerAPI::detectDevices() {
    std::vector<StorageDeviceDescriptor> result;
    auto detected = sanitization::DriveDetector::detectPhysicalDevices();

    for (const auto& d : detected) {
        StorageDeviceDescriptor desc;
        desc.deviceId = d.device_identifier;
        desc.name = d.target_path.empty() ? d.device_identifier : d.target_path;
        desc.model = d.model_name;
        desc.serialNumber = d.serial_number;
        desc.sizeBytes = d.total_bytes;
        desc.sectorSize = d.sector_size;
        desc.isPhysicalDevice = d.is_physical_device;
        desc.isSafeToSanitize = d.is_safe_to_sanitize;
        desc.isSystemOrRootDrive = core::Platform::isRootOrSystemPath(desc.name) || core::Platform::isRootOrSystemPath(desc.deviceId) || !d.is_safe_to_sanitize;
        desc.interfaceType = d.interface_type == sanitization::DriveInterface::NVME ? "NVMe" :
                             d.interface_type == sanitization::DriveInterface::SATA ? "SATA" :
                             d.interface_type == sanitization::DriveInterface::USB ? "USB" : "Unknown";
        desc.mediaType = d.media_type == sanitization::DriveMediaType::SSD_NAND ? "SSD" :
                         d.media_type == sanitization::DriveMediaType::HDD_ROTATIONAL ? "HDD" : "Other";
        desc.capabilities = d.capabilities;
        result.push_back(std::move(desc));
    }
    return result;
}

StorageDeviceDescriptor DriveSanitizerAPI::inspectDevice(const std::string& path) {
    auto d = sanitization::DriveDetector::detectImage(path, sanitization::DriveMediaType::DISK_IMAGE_RAW);
    StorageDeviceDescriptor desc;
    desc.deviceId = d.device_identifier;
    desc.name = d.target_path;
    desc.model = d.model_name;
    desc.serialNumber = d.serial_number;
    desc.sizeBytes = d.total_bytes;
    desc.sectorSize = d.sector_size;
    desc.isPhysicalDevice = d.is_physical_device;
    desc.isSafeToSanitize = d.is_safe_to_sanitize && !core::Platform::isRootOrSystemPath(path);
    desc.isSystemOrRootDrive = core::Platform::isRootOrSystemPath(path);
    desc.interfaceType = "VIRTUAL_IMAGE";
    desc.mediaType = "DISK_IMAGE_RAW";
    desc.capabilities = d.capabilities;
    return desc;
}

DriveSanitizeResult DriveSanitizerAPI::sanitize(const std::string& targetPath,
                                               DriveSanitizeStandard standard,
                                               DriveSanitizeProgressCallback cb) {
    DriveSanitizeResult result;
    result.targetDevice = targetPath;

    if (core::Platform::isRootOrSystemPath(targetPath) || core::Platform::isMainSystemDrive(targetPath)) {
        result.errorMessage = "Refusing to sanitize active OS root / system drive (" + targetPath + "). Protected even with root / admin privileges.";
        return result;
    }

    sanitization::ImageSanitizer sanitizer;
    std::unique_ptr<sanitization::SanitizationStrategy> strategy;
    switch (standard) {
        case DriveSanitizeStandard::DOD_5220_22_M:
            strategy = std::make_unique<sanitization::Dod522022MStrategy>();
            break;
        case DriveSanitizeStandard::CRYPTO_RANDOM:
            strategy = std::make_unique<sanitization::PseudorandomStrategy>();
            break;
        case DriveSanitizeStandard::NIST_800_88_CLEAR:
        default:
            strategy = std::make_unique<sanitization::NistClearStrategy>();
            break;
    }

    auto tStart = std::chrono::steady_clock::now();
    auto report = sanitizer.sanitizeImage(targetPath, *strategy, true, [cb](const sanitization::EraseProgress& p) {
        if (cb) {
            DriveSanitizeProgress dp;
            dp.bytesProcessed = p.total_bytes_processed;
            dp.totalBytes = p.total_bytes_all;
            dp.percentComplete = p.percentage;
            dp.currentPass = p.current_pass;
            dp.totalPasses = p.total_passes;
            cb(dp);
        }
    });
    auto tEnd = std::chrono::steady_clock::now();
    result.durationSeconds = std::chrono::duration<double>(tEnd - tStart).count();

    result.success = report.verified;
    result.totalBytesSanitized = report.total_bytes_sanitized;
    result.passesCompleted = report.passes_completed;
    result.verificationPassed = report.verified;
    result.auditSignature = report.audit_entry_hash;
    result.certificateJson = report.summary;
    if (!report.verified) {
        result.errorMessage = report.summary;
    }

    return result;
}

// ============================================================================
// CarverAPI Implementation
// ============================================================================

CarveSessionResult CarverAPI::carve(const std::string& imagePath,
                                    const std::string& outputDirectory,
                                    double minConfidence,
                                    CarveProgressCallback cb) {
    CarveSessionResult result;
    result.sourcePath = imagePath;
    result.outputDirectory = outputDirectory;

    core::DiskImageReader reader(imagePath);
    if (!reader.isOpen()) {
        result.errorMessage = "Failed to open image: " + reader.lastError();
        return result;
    }

    result.evidenceSizeBytes = reader.size();

    carving::CarverOptions options;
    options.outputDirectory = outputDirectory;
    options.organizeByType = true;
    options.validateIntegrity = true;
    options.minimumConfidence = minConfidence;

    carving::FileCarver carver(options);

    auto tStart = std::chrono::steady_clock::now();
    auto sessionRes = carver.carve(reader, [cb](uint64_t bytesProcessed, uint64_t totalBytes, size_t matchesFound) {
        if (cb) {
            CarveProgress cp;
            cp.bytesScanned = bytesProcessed;
            cp.totalBytes = totalBytes;
            cp.percentComplete = totalBytes > 0 ? (100.0 * bytesProcessed / totalBytes) : 0.0;
            cp.filesDiscovered = matchesFound;
            cb(cp);
        }
    });
    auto tEnd = std::chrono::steady_clock::now();

    result.success = true;
    result.signaturesDiscovered = sessionRes.signaturesDiscovered;
    result.filesSuccessfullyCarved = sessionRes.filesSuccessfullyCarved;
    result.validFilesCount = sessionRes.validFilesCount;
    result.durationSeconds = std::chrono::duration<double>(tEnd - tStart).count();

    for (const auto& cf : sessionRes.carvedFiles) {
        CarvedFileItem item;
        item.fileType = cf.fileType;
        item.offset = cf.startOffset;
        item.lengthBytes = cf.lengthBytes;
        item.isValid = cf.isValid;
        item.confidenceScore = cf.confidenceScore;
        item.recoveredFilePath = cf.recoveredFilePath;
        item.sha256 = cf.sha256;
        item.validationDetails = cf.validationNotes;
        result.carvedFiles.push_back(std::move(item));
    }

    return result;
}

// ============================================================================
// FsRecoveryAPI Implementation
// ============================================================================

VolumeMetadata FsRecoveryAPI::probeVolume(const std::string& imagePath, uint64_t partitionOffset) {
    VolumeMetadata meta;
    core::DiskImageReader reader(imagePath);
    if (!reader.isOpen()) return meta;

    // Try FAT32
    filesystem::FAT32Analyzer fat32;
    if (fat32.probe(reader, partitionOffset)) {
        auto vol = fat32.getVolumeInfo();
        meta.valid = true;
        meta.type = FilesystemType::FAT32;
        meta.label = vol.volume_label;
        meta.sectorSize = vol.bytes_per_sector;
        meta.sectorsPerCluster = vol.sectors_per_cluster;
        meta.clusterSize = vol.cluster_size;
        meta.totalClusters = vol.total_clusters;
        return meta;
    }

    // Try exFAT
    filesystem::ExFATAnalyzer exfat;
    if (exfat.probe(reader, partitionOffset)) {
        auto vol = exfat.getVolumeInfo();
        meta.valid = true;
        meta.type = FilesystemType::EXFAT;
        meta.label = vol.volume_label;
        meta.sectorSize = vol.bytes_per_sector;
        meta.sectorsPerCluster = vol.sectors_per_cluster;
        meta.clusterSize = vol.cluster_size;
        meta.totalClusters = vol.total_clusters;
        return meta;
    }

    // Try NTFS
    filesystem::NTFSAnalyzer ntfs;
    if (ntfs.probe(reader, partitionOffset)) {
        auto vol = ntfs.getVolumeInfo();
        meta.valid = true;
        meta.type = FilesystemType::NTFS;
        meta.label = vol.volume_label;
        meta.sectorSize = vol.bytes_per_sector;
        meta.sectorsPerCluster = vol.sectors_per_cluster;
        meta.clusterSize = vol.cluster_size;
        meta.totalClusters = vol.total_clusters;
        return meta;
    }

    return meta;
}

FilesystemRecoverySummary FsRecoveryAPI::recover(const std::string& imagePath,
                                               const std::string& outputDirectory,
                                               uint64_t /*partitionOffset*/) {
    FilesystemRecoverySummary summary;
    core::DiskImageReader reader(imagePath);
    if (!reader.isOpen()) {
        summary.errorMessage = "Failed to open image: " + reader.lastError();
        return summary;
    }

    recovery::RecoveryEngine engine;
    recovery::CaseContext ctx;
    auto rep = engine.runRecovery(reader, outputDirectory, ctx);

    summary.success = rep.fs_detected;
    summary.type = rep.fs_type == filesystem::FsType::FAT32 ? FilesystemType::FAT32 :
                   rep.fs_type == filesystem::FsType::EXFAT ? FilesystemType::EXFAT :
                   rep.fs_type == filesystem::FsType::NTFS  ? FilesystemType::NTFS  : FilesystemType::UNKNOWN;

    for (const auto& f : rep.filesystem_active_files) {
        RecoveredFileEntry entry;
        entry.filename = f.filename;
        entry.extension = f.extension;
        entry.sizeBytes = f.file_size;
        entry.isDeleted = false;
        entry.clusterOrMft = f.starting_cluster;
        entry.recoveredFilePath = f.full_path;
        entry.sha256 = f.sha256_hash;
        summary.activeFiles.push_back(std::move(entry));
    }

    for (const auto& f : rep.filesystem_deleted_files) {
        RecoveredFileEntry entry;
        entry.filename = f.filename;
        entry.extension = f.extension;
        entry.sizeBytes = f.file_size;
        entry.isDeleted = true;
        entry.clusterOrMft = f.starting_cluster;
        entry.recoveredFilePath = f.full_path;
        entry.sha256 = f.sha256_hash;
        summary.deletedFiles.push_back(std::move(entry));
    }

    return summary;
}

} // namespace forensivault::api
