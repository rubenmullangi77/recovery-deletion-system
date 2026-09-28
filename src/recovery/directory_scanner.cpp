#include "recovery/directory_scanner.hpp"
#include "forensivault/core/platform.hpp"
#include "core/disk_image_reader.hpp"
#include "filesystem/fat32_analyzer.hpp"
#include "filesystem/exfat_analyzer.hpp"
#include "filesystem/ntfs_analyzer.hpp"
#include "recovery/recovery_engine.hpp"
#include "logging/audit_logger.hpp"
#include "forensivault/common/crypto_hash.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <chrono>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <system_error>
#include <iostream>

#if defined(__linux__) || defined(__unix__) || defined(__APPLE__)
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace fs = std::filesystem;

namespace forensivault::recovery {

namespace {

std::string normalizePathString(const std::string& path) {
    if (path.empty()) return "";
    std::error_code ec;
    fs::path p(path);
    if (fs::exists(p, ec)) {
        p = fs::canonical(p, ec);
    } else {
        p = fs::absolute(p, ec);
    }
    std::string s = p.lexically_normal().string();
    // Strip trailing slashes unless it's root
    while (s.size() > 1 && (s.back() == '/' || s.back() == '\\')) {
        s.pop_back();
    }
#if defined(_WIN32)
    std::replace(s.begin(), s.end(), '/', '\\');
#endif
    return s;
}

bool pathStartsWith(const std::string& fullPath, const std::string& prefix) {
    if (fullPath == prefix) return true;
    if (fullPath.size() <= prefix.size()) return false;
    
#if defined(_WIN32)
    std::string fLower = fullPath;
    std::string pLower = prefix;
    std::transform(fLower.begin(), fLower.end(), fLower.begin(), ::tolower);
    std::transform(pLower.begin(), pLower.end(), pLower.begin(), ::tolower);
    if (fLower == pLower) return true;
    if (fLower.rfind(pLower, 0) == 0) {
        char sep = fLower[pLower.size()];
        return (sep == '\\' || sep == '/');
    }
    return false;
#else
    if (fullPath.rfind(prefix, 0) == 0) {
        char sep = fullPath[prefix.size()];
        return (sep == '/');
    }
    return false;
#endif
}

uint64_t computeDirectoryRecursiveSize(const fs::path& dirPath) {
    uint64_t total = 0;
    std::error_code ec;
    if (!fs::exists(dirPath, ec) || !fs::is_directory(dirPath, ec)) return 0;
    for (const auto& entry : fs::recursive_directory_iterator(dirPath, fs::directory_options::skip_permission_denied, ec)) {
        if (!entry.is_directory(ec)) {
            total += entry.file_size(ec);
        }
    }
    return total;
}

std::string computeFileSha256(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open()) return "";
    CryptoHash::Sha256Context ctx;
    char buf[65536];
    while (ifs.read(buf, sizeof(buf)) || ifs.gcount() > 0) {
        ctx.update(reinterpret_cast<const uint8_t*>(buf), ifs.gcount());
    }
    return ctx.finalize();
}

} // anonymous namespace

std::string DirectoryScanner::urlDecode(const std::string& str) {
    std::string result;
    result.reserve(str.size());
    for (size_t i = 0; i < str.size(); ++i) {
        if (str[i] == '%' && i + 2 < str.size()) {
            auto fromHex = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            int h = fromHex(str[i + 1]);
            int l = fromHex(str[i + 2]);
            if (h >= 0 && l >= 0) {
                result.push_back(static_cast<char>((h << 4) | l));
                i += 2;
                continue;
            }
        }
        result.push_back(str[i]);
    }
    return result;
}

DirectoryMountInfo DirectoryScanner::resolveMountInfo(const std::string& directoryPath) {
    DirectoryMountInfo info;
    info.directory_path = normalizePathString(directoryPath);
    info.mount_point = "/";
    info.filesystem_type = "unknown";
    info.device_path = "";
    info.total_bytes = 0;
    info.free_bytes = 0;
    info.is_device_readable = false;

    if (info.directory_path.empty()) {
        return info;
    }

#if defined(__linux__)
    // 1. Resolve mount point and device from /proc/mounts
    std::ifstream mountsFile("/proc/mounts");
    if (mountsFile.is_open()) {
        std::string line;
        size_t bestMatchLen = 0;
        std::string bestMountPoint = "/";
        std::string bestFsType = "ext4";
        std::string bestDevice = "";

        while (std::getline(mountsFile, line)) {
            std::istringstream iss(line);
            std::string mDev, mPoint, mType;
            if (iss >> mDev >> mPoint >> mType) {
                if (pathStartsWith(info.directory_path, mPoint) && mPoint.size() >= bestMatchLen) {
                    bestMatchLen = mPoint.size();
                    bestMountPoint = mPoint;
                    bestFsType = mType;
                    bestDevice = mDev;
                }
            }
        }

        info.mount_point = bestMountPoint;
        info.filesystem_type = bestFsType;
        info.device_path = bestDevice;
    }

    // 2. Query volume capacity via statvfs
    struct statvfs svfs{};
    if (::statvfs(info.directory_path.c_str(), &svfs) == 0) {
        info.total_bytes = static_cast<uint64_t>(svfs.f_blocks) * svfs.f_frsize;
        info.free_bytes = static_cast<uint64_t>(svfs.f_bavail) * svfs.f_frsize;
    }

    // 3. Check if underlying device is directly readable
    if (!info.device_path.empty() && info.device_path.rfind("/dev/", 0) == 0) {
        int fd = ::open(info.device_path.c_str(), O_RDONLY);
        if (fd >= 0) {
            info.is_device_readable = true;
            ::close(fd);
        }
    }

#elif defined(_WIN32)
    std::wstring wDirPath(info.directory_path.begin(), info.directory_path.end());
    wchar_t volumePath[MAX_PATH] = {0};
    if (GetVolumePathNameW(wDirPath.c_str(), volumePath, MAX_PATH)) {
        std::wstring wVol(volumePath);
        info.mount_point = std::string(wVol.begin(), wVol.end());
        if (info.mount_point.size() >= 2 && info.mount_point[1] == ':') {
            info.device_path = "\\\\.\\" + info.mount_point.substr(0, 2);
        }
    }

    wchar_t fsName[MAX_PATH] = {0};
    DWORD serialNumber = 0, maxComponentLen = 0, flags = 0;
    if (GetVolumeInformationW(volumePath, NULL, 0, &serialNumber, &maxComponentLen, &flags, fsName, MAX_PATH)) {
        std::wstring wFs(fsName);
        info.filesystem_type = std::string(wFs.begin(), wFs.end());
    }

    ULARGE_INTEGER freeBytesAvail, totalBytes, totalFreeBytes;
    if (GetDiskFreeSpaceExW(wDirPath.c_str(), &freeBytesAvail, &totalBytes, &totalFreeBytes)) {
        info.total_bytes = totalBytes.QuadPart;
        info.free_bytes = freeBytesAvail.QuadPart;
    }

    if (!info.device_path.empty()) {
        std::wstring wDev(info.device_path.begin(), info.device_path.end());
        HANDLE hDev = CreateFileW(wDev.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  NULL, OPEN_EXISTING, 0, NULL);
        if (hDev != INVALID_HANDLE_VALUE) {
            info.is_device_readable = true;
            CloseHandle(hDev);
        }
    }
#endif

    return info;
}

std::vector<ScannedDeletedItem> DirectoryScanner::scanTrashJournals(
    const std::string& directoryPath, const DirectoryMountInfo& mountInfo) {
    
    std::vector<ScannedDeletedItem> items;
    std::string normDirPath = normalizePathString(directoryPath);
    if (normDirPath.empty()) return items;

    std::vector<fs::path> candidateTrashDirs;

#if defined(__linux__) || defined(__unix__) || defined(__APPLE__)
    // 1. User's standard FreeDesktop trash in ~/.local/share/Trash
    std::string homeDir = core::Platform::getUserHomeDirectory();
    if (!homeDir.empty() && homeDir != ".") {
        candidateTrashDirs.push_back(fs::path(homeDir) / ".local" / "share" / "Trash");
    }

    // 2. If running elevated / root, also check /root/.local/share/Trash
    if (core::Platform::isElevated()) {
        candidateTrashDirs.push_back(fs::path("/root/.local/share/Trash"));
    }

    // 3. Check XDG_DATA_HOME/Trash if configured
    const char* xdgDataHome = std::getenv("XDG_DATA_HOME");
    if (xdgDataHome && *xdgDataHome) {
        candidateTrashDirs.push_back(fs::path(xdgDataHome) / "Trash");
    }

    // 4. Check mount point specific trash directories (.Trash/<uid>, .Trash-<uid>)
    if (!mountInfo.mount_point.empty() && mountInfo.mount_point != "/") {
        fs::path mnt(mountInfo.mount_point);
        candidateTrashDirs.push_back(mnt / ".Trash");
        candidateTrashDirs.push_back(mnt / ".trash");
        uid_t uid = getuid();
        candidateTrashDirs.push_back(mnt / ".Trash" / std::to_string(uid));
        candidateTrashDirs.push_back(mnt / (".Trash-" + std::to_string(uid)));
    }

    // 5. Target directory itself or immediate ancestors might contain a localized .Trash
    candidateTrashDirs.push_back(fs::path(normDirPath) / ".Trash");
    candidateTrashDirs.push_back(fs::path(normDirPath) / ".trash");

    // Remove duplicates
    std::vector<fs::path> uniqueTrashDirs;
    std::error_code ec;
    for (const auto& td : candidateTrashDirs) {
        if (!fs::exists(td, ec)) continue;
        bool existsAlready = false;
        for (const auto& u : uniqueTrashDirs) {
            if (fs::equivalent(td, u, ec)) {
                existsAlready = true;
                break;
            }
        }
        if (!existsAlready) uniqueTrashDirs.push_back(td);
    }

    uint64_t itemCounter = 1;

    for (const auto& trashRoot : uniqueTrashDirs) {
        fs::path infoDir = trashRoot / "info";
        fs::path filesDir = trashRoot / "files";

        if (!fs::exists(infoDir, ec) || !fs::is_directory(infoDir, ec)) {
            continue;
        }

        for (const auto& entry : fs::directory_iterator(infoDir, fs::directory_options::skip_permission_denied, ec)) {
            if (!entry.is_regular_file(ec)) continue;
            std::string filename = entry.path().filename().string();
            if (filename.size() <= 10 || filename.rfind(".trashinfo") != (filename.size() - 10)) {
                continue;
            }

            // Read .trashinfo file
            std::ifstream ifs(entry.path());
            if (!ifs.is_open()) continue;

            std::string originalPath;
            std::string deletionDate;
            std::string line;

            while (std::getline(ifs, line)) {
                // Strip carriage return
                if (!line.empty() && line.back() == '\r') line.pop_back();

                if (line.rfind("Path=", 0) == 0) {
                    originalPath = urlDecode(line.substr(5));
                } else if (line.rfind("DeletionDate=", 0) == 0) {
                    deletionDate = line.substr(13);
                }
            }

            if (originalPath.empty()) continue;

            std::string normOrig = normalizePathString(originalPath);
            if (!pathStartsWith(normOrig, normDirPath)) {
                continue; // Not deleted from this directory
            }

            // Payload filename inside files/
            std::string basePayloadName = filename.substr(0, filename.size() - 10);
            fs::path payloadPath = filesDir / basePayloadName;

            if (!fs::exists(payloadPath, ec)) {
                continue; // Payload was already permanently purged
            }

            bool isDir = fs::is_directory(payloadPath, ec);
            uint64_t sz = isDir ? computeDirectoryRecursiveSize(payloadPath) : fs::file_size(payloadPath, ec);

            ScannedDeletedItem item;
            item.id = "TRASH_" + std::to_string(itemCounter++);
            item.filename = fs::path(normOrig).filename().string();
            if (item.filename.empty()) item.filename = basePayloadName;
            item.original_path = normOrig;
            
            // Relative path calculation
            if (normOrig.size() > normDirPath.size()) {
                size_t startIdx = normDirPath.size();
                while (startIdx < normOrig.size() && (normOrig[startIdx] == '/' || normOrig[startIdx] == '\\')) {
                    startIdx++;
                }
                item.relative_path = normOrig.substr(startIdx);
            } else {
                item.relative_path = item.filename;
            }

            item.extension = fs::path(normOrig).extension().string();
            if (!item.extension.empty() && item.extension.front() == '.') {
                item.extension = item.extension.substr(1);
            }

            item.size_bytes = sz;
            item.is_directory = isDir;
            item.source = DeletedItemSource::TRASH_JOURNAL;
            item.confidence_score = 100;
            item.confidence_level = "High";
            item.deletion_timestamp = deletionDate.empty() ? "Recorded in Trash Journal" : deletionDate;
            item.payload_location = payloadPath.string();
            item.selected = true;

            items.push_back(std::move(item));
        }
    }

#elif defined(_WIN32)
    // Windows Recycle Bin parsing ($Recycle.Bin\<SID>\$I* -> $R*)
    std::string driveRoot = mountInfo.mount_point;
    if (driveRoot.empty() && normDirPath.size() >= 2 && normDirPath[1] == ':') {
        driveRoot = normDirPath.substr(0, 2) + "\\";
    }

    if (!driveRoot.empty()) {
        fs::path recycleRoot = fs::path(driveRoot) / "$Recycle.Bin";
        std::error_code ec;
        if (fs::exists(recycleRoot, ec)) {
            uint64_t itemCounter = 1;
            for (const auto& sidDir : fs::directory_iterator(recycleRoot, fs::directory_options::skip_permission_denied, ec)) {
                if (!sidDir.is_directory(ec)) continue;

                for (const auto& recEntry : fs::directory_iterator(sidDir.path(), fs::directory_options::skip_permission_denied, ec)) {
                    std::string fName = recEntry.path().filename().string();
                    if (fName.size() >= 3 && fName[0] == '$' && (fName[1] == 'I' || fName[1] == 'i')) {
                        // Metadata header $I file
                        std::ifstream metaFile(recEntry.path(), std::ios::binary);
                        if (!metaFile) continue;

                        std::vector<uint8_t> metaBuf((std::istreambuf_iterator<char>(metaFile)),
                                                     std::istreambuf_iterator<char>());
                        if (metaBuf.size() < 24) continue;

                        uint64_t version = *reinterpret_cast<const uint64_t*>(metaBuf.data());
                        uint64_t origSize = *reinterpret_cast<const uint64_t*>(metaBuf.data() + 8);
                        
                        std::wstring wOrigPath;
                        if (version == 1 && metaBuf.size() >= 24 + 260 * sizeof(wchar_t)) {
                            wOrigPath = reinterpret_cast<const wchar_t*>(metaBuf.data() + 24);
                        } else if (version == 2 && metaBuf.size() >= 28) {
                            uint32_t charCount = *reinterpret_cast<const uint32_t*>(metaBuf.data() + 24);
                            if (metaBuf.size() >= 28 + charCount * sizeof(wchar_t)) {
                                wOrigPath = std::wstring(reinterpret_cast<const wchar_t*>(metaBuf.data() + 28), charCount);
                            }
                        }

                        if (wOrigPath.empty()) continue;
                        std::string origPath(wOrigPath.begin(), wOrigPath.end());
                        std::string normOrig = normalizePathString(origPath);

                        if (!pathStartsWith(normOrig, normDirPath)) {
                            continue;
                        }

                        // Payload counterpart replaces '$I' with '$R'
                        std::string rName = fName;
                        rName[1] = 'R';
                        fs::path rPath = sidDir.path() / rName;
                        if (!fs::exists(rPath, ec)) continue;

                        bool isDir = fs::is_directory(rPath, ec);
                        ScannedDeletedItem item;
                        item.id = "RECYCLE_" + std::to_string(itemCounter++);
                        item.filename = fs::path(normOrig).filename().string();
                        item.original_path = normOrig;
                        item.relative_path = item.filename;
                        item.extension = fs::path(normOrig).extension().string();
                        if (!item.extension.empty() && item.extension.front() == '.') {
                            item.extension = item.extension.substr(1);
                        }
                        item.size_bytes = isDir ? computeDirectoryRecursiveSize(rPath) : origSize;
                        item.is_directory = isDir;
                        item.source = DeletedItemSource::TRASH_JOURNAL;
                        item.confidence_score = 100;
                        item.confidence_level = "High";
                        item.deletion_timestamp = "Windows Recycle Bin Record";
                        item.payload_location = rPath.string();
                        item.selected = true;

                        items.push_back(std::move(item));
                    }
                }
            }
        }
    }
#endif

    return items;
}

std::vector<ScannedDeletedItem> DirectoryScanner::scanFilesystemMetadata(
    const std::string& directoryPath, const DirectoryMountInfo& mountInfo) {
    
    std::vector<ScannedDeletedItem> items;
    if (!mountInfo.is_device_readable || mountInfo.device_path.empty()) {
        return items;
    }

    core::DiskImageReader reader(mountInfo.device_path);
    if (!reader.isOpen()) {
        return items;
    }

    recovery::RecoveryEngine engine;
    auto analyzer = engine.detectFilesystem(reader, 0);
    if (!analyzer) {
        return items;
    }

    std::string normDirPath = normalizePathString(directoryPath);
    auto deletedRecords = analyzer->findDeletedFiles();
    uint64_t counter = 1;

    for (const auto& rec : deletedRecords) {
        ScannedDeletedItem item;
        item.id = "FS_META_" + std::to_string(counter++);
        item.filename = rec.filename;
        item.original_path = normDirPath + "/" + rec.filename;
        item.relative_path = rec.filename;
        item.extension = rec.extension;
        item.size_bytes = rec.file_size;
        item.is_directory = rec.is_directory;
        item.source = DeletedItemSource::FILESYSTEM_METADATA;
        item.confidence_score = (rec.confidence_score > 0) ? rec.confidence_score : 85;
        item.confidence_level = (item.confidence_score >= 80) ? "High" : (item.confidence_score >= 60) ? "Medium" : "Low";
        item.deletion_timestamp = rec.modified_time.empty() ? "Filesystem Tombstone" : rec.modified_time;
        item.payload_location = "fs_meta:" + std::to_string(rec.starting_cluster) + ":" + std::to_string(rec.file_size);
        item.selected = true;

        items.push_back(std::move(item));
    }

    return items;
}

std::vector<ScannedDeletedItem> DirectoryScanner::scanSanitizedAuditRecords(const std::string& directoryPath) {
    std::vector<ScannedDeletedItem> items;
    std::string normDirPath = normalizePathString(directoryPath);
    if (normDirPath.empty()) return items;

    auto& logger = logging::AuditLogger::getInstance();
    auto entries = logger.getEntries();

    // If in-memory audit log has no entries, try loading from default persistent journal
    if (entries.empty()) {
        fs::path configDir = core::Platform::getConfigDirectory();
        fs::path textJournal = configDir / "audit_log.txt";
        fs::path legacyJournal = configDir / "audit_journal.jsonl";
        std::error_code ec;
        if (fs::exists(textJournal, ec)) {
            logger.loadFromFile(textJournal.string());
            entries = logger.getEntries();
        } else if (fs::exists(legacyJournal, ec)) {
            logger.loadFromFile(legacyJournal.string());
            entries = logger.getEntries();
        }
    }

    std::vector<std::string> seenPaths;
    uint64_t counter = 1;

    // Scan backwards (most recent sanitization events first)
    for (auto it = entries.rbegin(); it != entries.rend(); ++it) {
        const auto& entry = *it;
        if (entry.operation_type != "SECURE_FILE_ERASE" &&
            entry.operation_type != "SECURE_FOLDER_ERASE") {
            continue;
        }

        std::string normTarget = normalizePathString(entry.source_identifier);
        if (normTarget.empty()) continue;

        // Check if the sanitized path is inside or identical to directoryPath
        if (!pathStartsWith(normTarget, normDirPath)) {
            continue;
        }

        // Avoid duplicates if the exact same path was sanitized multiple times
        if (std::find(seenPaths.begin(), seenPaths.end(), normTarget) != seenPaths.end()) {
            continue;
        }
        seenPaths.push_back(normTarget);

        ScannedDeletedItem item;
        item.id = "SANITIZED_" + std::to_string(entry.entry_id > 0 ? entry.entry_id : counter++);
        item.filename = fs::path(normTarget).filename().string();
        if (item.filename.empty()) item.filename = normTarget;
        item.original_path = normTarget;

        if (normTarget.size() > normDirPath.size()) {
            size_t startIdx = normDirPath.size();
            while (startIdx < normTarget.size() && (normTarget[startIdx] == '/' || normTarget[startIdx] == '\\')) {
                startIdx++;
            }
            item.relative_path = normTarget.substr(startIdx);
        } else {
            item.relative_path = item.filename;
        }

        item.extension = fs::path(normTarget).extension().string();
        if (!item.extension.empty() && item.extension.front() == '.') {
            item.extension = item.extension.substr(1);
        }

        item.is_directory = (entry.operation_type == "SECURE_FOLDER_ERASE");
        item.source = DeletedItemSource::SANITIZED_AUDIT;
        item.confidence_score = 0;
        item.confidence_level = "Irrecoverable";
        item.deletion_timestamp = entry.timestamp_iso.empty() ? "Recorded in Audit Log" : entry.timestamp_iso;
        item.payload_location = "Sanitized via " + entry.method + " [" + entry.status + "]: Overwritten & Scrambled";
        item.selected = false; // Cannot be restored
        item.size_bytes = 0;

        items.push_back(std::move(item));
    }

    return items;
}

DirectoryScanOutput DirectoryScanner::scanDirectory(const std::string& directoryPath) {
    auto startTime = std::chrono::steady_clock::now();
    DirectoryScanOutput output;

    if (directoryPath.empty()) {
        output.success = false;
        output.error_message = "Target directory path cannot be empty.";
        return output;
    }

    std::error_code ec;
    fs::path p(directoryPath);
    if (!fs::exists(p, ec)) {
        output.success = false;
        output.error_message = "Specified directory does not exist: " + directoryPath;
        return output;
    }

    output.mount_info = resolveMountInfo(directoryPath);

    // 1. Scan trash journals (FreeDesktop trash & Windows Recycle Bin)
    auto trashItems = scanTrashJournals(directoryPath, output.mount_info);
    for (auto& it : trashItems) {
        output.items.push_back(std::move(it));
    }

    // 2. Scan volume filesystem metadata structures if block device is directly readable
    if (output.mount_info.is_device_readable) {
        auto fsItems = scanFilesystemMetadata(directoryPath, output.mount_info);
        for (auto& it : fsItems) {
            output.items.push_back(std::move(it));
        }
    }

    // 3. Scan cryptographic audit records for files/folders sanitized through ForensiVault
    auto sanitizedItems = scanSanitizedAuditRecords(directoryPath);
    for (auto& it : sanitizedItems) {
        output.items.push_back(std::move(it));
    }

    auto endTime = std::chrono::steady_clock::now();
    output.duration_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count());
    output.success = true;

    return output;
}

DirectoryRecoveryOutput DirectoryScanner::recoverItems(
    const std::string& directoryPath,
    const std::vector<ScannedDeletedItem>& itemsToRecover,
    const std::string& outputDirectory) {
    
    DirectoryRecoveryOutput out;
    out.requested_count = itemsToRecover.size();

    if (outputDirectory.empty()) {
        out.success = false;
        out.error_message = "Destination output directory cannot be empty.";
        return out;
    }

    std::string normScanned = normalizePathString(directoryPath);
    std::string normDest = normalizePathString(outputDirectory);

    // Safety check: Prevent writing recovered files inside the directory being scanned
    if (pathStartsWith(normDest, normScanned)) {
        out.success = false;
        out.error_message = "Safety Violation: Destination output directory cannot reside inside the directory being recovered. "
                            "Please choose an external directory to prevent unallocated cluster corruption.";
        return out;
    }

    std::error_code ec;
    fs::create_directories(normDest, ec);
    if (ec) {
        out.success = false;
        out.error_message = "Failed to create output destination directory: " + ec.message();
        return out;
    }

    auto mountInfo = resolveMountInfo(directoryPath);
    std::unique_ptr<core::DiskImageReader> fsReader;
    std::unique_ptr<filesystem::FilesystemAnalyzer> fsAnalyzer;

    if (mountInfo.is_device_readable && !mountInfo.device_path.empty()) {
        fsReader = std::make_unique<core::DiskImageReader>(mountInfo.device_path);
        if (fsReader->isOpen()) {
            recovery::RecoveryEngine eng;
            fsAnalyzer = eng.detectFilesystem(*fsReader, 0);
        }
    }

    for (const auto& item : itemsToRecover) {
        if (item.filename.empty()) continue;

        if (item.source == DeletedItemSource::SANITIZED_AUDIT) {
            out.errors.push_back("Cannot recover '" + item.filename + "': Data was permanently destroyed via certified multi-pass sanitization (NIST SP 800-88 / DoD).");
            continue;
        }

        fs::path targetFilePath = fs::path(normDest) / item.filename;

        // Collision avoidance: if destination file exists, append _recovered_1, etc.
        int collisionIndex = 1;
        while (fs::exists(targetFilePath, ec)) {
            std::string stem = fs::path(item.filename).stem().string();
            std::string ext = fs::path(item.filename).extension().string();
            targetFilePath = fs::path(normDest) / (stem + "_recovered_" + std::to_string(collisionIndex++) + ext);
        }

        bool itemRecovered = false;

        if (item.source == DeletedItemSource::TRASH_JOURNAL) {
            fs::path payload(item.payload_location);
            if (fs::exists(payload, ec)) {
                if (item.is_directory) {
                    fs::copy(payload, targetFilePath, fs::copy_options::recursive | fs::copy_options::overwrite_existing, ec);
                    if (!ec) {
                        itemRecovered = true;
                        out.recovered_bytes += item.size_bytes;
                    } else {
                        out.errors.push_back("Failed to copy directory payload for '" + item.filename + "': " + ec.message());
                    }
                } else {
                    fs::copy_file(payload, targetFilePath, fs::copy_options::overwrite_existing, ec);
                    if (!ec) {
                        itemRecovered = true;
                        out.recovered_bytes += fs::file_size(targetFilePath, ec);
                    } else {
                        out.errors.push_back("Failed to copy file payload for '" + item.filename + "': " + ec.message());
                    }
                }
            } else {
                out.errors.push_back("Trash journal payload file not found for '" + item.filename + "'");
            }
        } else if (item.source == DeletedItemSource::FILESYSTEM_METADATA && fsAnalyzer && fsReader) {
            // Parse cluster and size from payload_location ("fs_meta:<cluster>:<size>")
            uint64_t cluster = 0;
            uint64_t fsize = item.size_bytes;
            if (item.payload_location.rfind("fs_meta:", 0) == 0) {
                size_t firstColon = item.payload_location.find(':');
                size_t secondColon = item.payload_location.find(':', firstColon + 1);
                if (firstColon != std::string::npos && secondColon != std::string::npos) {
                    cluster = std::stoull(item.payload_location.substr(firstColon + 1, secondColon - firstColon - 1));
                    fsize = std::stoull(item.payload_location.substr(secondColon + 1));
                }
            }

            filesystem::FsFileRecord rec;
            rec.filename = item.filename;
            rec.extension = item.extension;
            rec.file_size = fsize;
            rec.starting_cluster = cluster;
            rec.allocation_status = filesystem::AllocationStatus::DELETED_CANDIDATE;
            rec.recovery_method = filesystem::RecoveryMethod::FILESYSTEM_METADATA_DELETED;

            auto data = fsAnalyzer->extractFile(rec, *fsReader);
            if (!data.empty()) {
                std::ofstream ofs(targetFilePath, std::ios::binary);
                if (ofs) {
                    ofs.write(reinterpret_cast<const char*>(data.data()), data.size());
                    itemRecovered = true;
                    out.recovered_bytes += data.size();
                }
            } else {
                out.errors.push_back("Failed to extract filesystem cluster data for '" + item.filename + "'");
            }
        }

        if (itemRecovered) {
            out.recovered_count++;
            out.recovered_files.push_back(targetFilePath.string());
        }
    }

    out.success = (out.recovered_count > 0 || itemsToRecover.empty());

    // Record forensic audit log entry
    logging::AuditEntry auditEntry;
    auditEntry.operation_type = "DIRECTORY_DELETED_RECOVERY";
    auditEntry.source_identifier = normScanned;
    auditEntry.method = "Multi-Source Directory & Journal Scanning (FreeDesktop / MFT / FAT32)";
    auditEntry.status = out.success ? "SUCCESS" : "PARTIAL_FAILURE";
    auditEntry.details = "Recovered " + std::to_string(out.recovered_count) + " / " +
                         std::to_string(out.requested_count) + " items into '" + normDest + "'. " +
                         "Total recovered size: " + std::to_string(out.recovered_bytes) + " bytes.";

    uint64_t artifactId = 1;
    for (const auto& rPath : out.recovered_files) {
        logging::RecoveredArtifactRecord rec;
        rec.file_id = artifactId++;
        rec.filename = fs::path(rPath).filename().string();
        rec.relative_path = rPath;
        rec.size_bytes = fs::exists(rPath, ec) ? fs::file_size(rPath, ec) : 0;
        rec.sha256_hash = computeFileSha256(rPath);
        rec.confidence_score = 100;
        rec.confidence_level = "High";
        rec.validation_status = "RECOVERED";
        auditEntry.recovered_artifacts.push_back(rec);
    }

    logging::CustodyEvent custodyEv;
    custodyEv.timestamp_iso = logging::AuditLogger::currentTimestampIso();
    custodyEv.action = "DIRECTORY_RESTORE";
    custodyEv.custodian = "Forensic Analyst";
    custodyEv.location = "Forensic Workstation";
    custodyEv.notes = "Executed non-destructive restore of deleted directory items from " + normScanned + " to " + normDest;
    auditEntry.chain_of_custody.push_back(custodyEv);

    logging::AuditLogger::getInstance().logForensicOperation(auditEntry);

    return out;
}

} // namespace forensivault::recovery
