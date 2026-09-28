#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <functional>
#include <ostream>
#include <algorithm>
#include <cctype>

#include <filesystem>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace forensivault {
namespace sanitization {

enum class TargetType {
    REGULAR_FILE,          // Host filesystem regular file (subject to host FS metadata, single handle, in-place overwrite, unlink)
    DISK_IMAGE,            // Forensic container file (.img, .raw, .dd)
    PHYSICAL_BLOCK_DEVICE  // Raw physical block device (/dev/sdX, \\.\PhysicalDriveN) - UNSUPPORTED in software layer
};

inline std::ostream& operator<<(std::ostream& os, TargetType type) {
    switch (type) {
        case TargetType::REGULAR_FILE:          return os << "REGULAR_FILE";
        case TargetType::DISK_IMAGE:            return os << "DISK_IMAGE";
        case TargetType::PHYSICAL_BLOCK_DEVICE: return os << "PHYSICAL_BLOCK_DEVICE (UNSUPPORTED)";
        default:                                return os << "UNKNOWN";
    }
}

inline TargetType probeTargetType(const std::string& path) {
    if (path.empty()) return TargetType::REGULAR_FILE;
    if (path.rfind("/dev/", 0) == 0 || path.rfind("\\\\.\\", 0) == 0) {
        return TargetType::PHYSICAL_BLOCK_DEVICE;
    }
    std::error_code ec;
    std::filesystem::path p(path);
    if (std::filesystem::exists(p, ec)) {
        if (std::filesystem::is_block_file(p, ec) || std::filesystem::is_character_file(p, ec)) {
            return TargetType::PHYSICAL_BLOCK_DEVICE;
        }
    }
    std::string ext = p.extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    if (ext == ".img" || ext == ".raw" || ext == ".dd" || ext == ".vmdk" || ext == ".bin" || ext == ".iso") {
        return TargetType::DISK_IMAGE;
    }
    return TargetType::REGULAR_FILE;
}

struct TargetIdentity {
    TargetType type{TargetType::REGULAR_FILE};
    std::string canonical_path;
    std::string original_path;
    uint64_t size_bytes{0};
    bool valid{false};
    bool path_resolved_from_handle{false};

#if defined(_WIN32)
    uint32_t volume_serial_number{0};
    uint32_t file_index_high{0};
    uint32_t file_index_low{0};
    uint32_t file_attributes{0};
    uint32_t number_of_links{0};
#else
    uint64_t device_id{0};       // st_dev
    uint64_t inode_number{0};     // st_ino
    uint32_t mode{0};             // st_mode
    uint32_t hard_link_count{0};  // st_nlink
    int64_t mtime_sec{0};         // st_mtime
    int64_t mtime_nsec{0};
#endif

    bool matches(const TargetIdentity& other) const noexcept {
        if (!valid || !other.valid || type != other.type) {
            return false;
        }
#if defined(_WIN32)
        return volume_serial_number == other.volume_serial_number &&
               file_index_high == other.file_index_high &&
               file_index_low == other.file_index_low;
#else
        return device_id == other.device_id && inode_number == other.inode_number;
#endif
    }

    bool matchesPath(const std::string& path) const noexcept {
        if (!valid || path.empty()) {
            return false;
        }
#if defined(_WIN32)
        HANDLE h = CreateFileA(
            path.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            NULL
        );
        if (h == INVALID_HANDLE_VALUE) {
            return false;
        }
        BY_HANDLE_FILE_INFORMATION bhfi{};
        BOOL ok = GetFileInformationByHandle(h, &bhfi);
        CloseHandle(h);
        if (!ok) return false;
        if (bhfi.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) {
            return false;
        }
        return volume_serial_number == bhfi.dwVolumeSerialNumber &&
               file_index_high == bhfi.nFileIndexHigh &&
               file_index_low == bhfi.nFileIndexLow &&
               bhfi.nNumberOfLinks == 1;
#else
        struct stat st{};
        if (::lstat(path.c_str(), &st) != 0) {
            return false;
        }
        if (S_ISLNK(st.st_mode) || !S_ISREG(st.st_mode)) {
            return false;
        }
        return static_cast<uint64_t>(st.st_dev) == device_id &&
               static_cast<uint64_t>(st.st_ino) == inode_number &&
               static_cast<uint32_t>(st.st_nlink) == 1;
#endif
    }
};

#if defined(_WIN32)
inline TargetIdentity captureIdentityFromHandle(HANDLE hFile, const std::string& path, TargetType type) {
    TargetIdentity id;
    id.original_path = path;
    id.type = type;
    if (hFile != INVALID_HANDLE_VALUE && hFile != NULL) {
        BY_HANDLE_FILE_INFORMATION bhfi{};
        if (GetFileInformationByHandle(hFile, &bhfi)) {
            id.volume_serial_number = bhfi.dwVolumeSerialNumber;
            id.file_index_high = bhfi.nFileIndexHigh;
            id.file_index_low = bhfi.nFileIndexLow;
            id.file_attributes = bhfi.dwFileAttributes;
            id.number_of_links = bhfi.nNumberOfLinks;
            id.size_bytes = (static_cast<uint64_t>(bhfi.nFileSizeHigh) << 32) | bhfi.nFileSizeLow;
            id.valid = true;

            char finalPath[MAX_PATH * 2] = {0};
            DWORD ret = GetFinalPathNameByHandleA(hFile, finalPath, sizeof(finalPath), FILE_NAME_NORMALIZED);
            if (ret > 0 && ret < sizeof(finalPath)) {
                std::string pStr(finalPath);
                if (pStr.rfind("\\\\?\\", 0) == 0) {
                    pStr = pStr.substr(4);
                }
                id.canonical_path = pStr;
                id.path_resolved_from_handle = true;
            } else {
                id.canonical_path.clear();
                id.path_resolved_from_handle = false;
            }
        }
    }
    return id;
}
#else
inline TargetIdentity captureIdentityFromFd(int fd, const std::string& path, TargetType type) {
    TargetIdentity id;
    id.original_path = path;
    id.type = type;
    struct stat st{};
    if (fd >= 0 && ::fstat(fd, &st) == 0) {
        id.device_id = static_cast<uint64_t>(st.st_dev);
        id.inode_number = static_cast<uint64_t>(st.st_ino);
        id.mode = static_cast<uint32_t>(st.st_mode);
        id.hard_link_count = static_cast<uint32_t>(st.st_nlink);
        id.size_bytes = static_cast<uint64_t>(st.st_size);
        id.mtime_sec = static_cast<int64_t>(st.st_mtime);
#if defined(__APPLE__)
        id.mtime_nsec = static_cast<int64_t>(st.st_mtimespec.tv_nsec);
#else
        id.mtime_nsec = static_cast<int64_t>(st.st_mtim.tv_nsec);
#endif
        id.valid = true;

        // Resolve actual path associated with already-open descriptor via /proc/self/fd/<fd>
        std::error_code ec;
        std::string procPath = "/proc/self/fd/" + std::to_string(fd);
        if (std::filesystem::exists(procPath, ec)) {
            std::filesystem::path real = std::filesystem::read_symlink(procPath, ec);
            if (!ec && !real.empty()) {
                id.canonical_path = real.string();
                id.path_resolved_from_handle = true;
            } else {
                id.canonical_path.clear();
                id.path_resolved_from_handle = false;
            }
        } else {
            id.canonical_path.clear();
            id.path_resolved_from_handle = false;
        }
    }
    return id;
}
#endif

enum class SanitizationMethod {
    NIST_800_88_CLEAR,     // 1-pass zero-fill (0x00) with buffer flush & readback verification
    DOD_5220_22_M,         // 3-pass overwrite (Pass 1: 0x00, Pass 2: 0xFF, Pass 3: CSPRNG random)
    PSEUDORANDOM_1_PASS,   // 1-pass CSPRNG random bytes
    ZERO_FILL              // Standard 1-pass zero-fill
};

inline std::ostream& operator<<(std::ostream& os, SanitizationMethod method) {
    switch (method) {
        case SanitizationMethod::NIST_800_88_CLEAR:   return os << "NIST SP 800-88 Rev 1 (Clear / Zero-fill)";
        case SanitizationMethod::DOD_5220_22_M:       return os << "DoD 5220.22-M (3-Pass)";
        case SanitizationMethod::PSEUDORANDOM_1_PASS: return os << "Pseudorandom (1-Pass)";
        case SanitizationMethod::ZERO_FILL:           return os << "Zero-Fill (1-Pass)";
        default:                                      return os << "UNKNOWN";
    }
}

inline std::string getMethodDescription(SanitizationMethod method) {
    switch (method) {
        case SanitizationMethod::NIST_800_88_CLEAR:
            return "Complies with NIST SP 800-88 Rev 1 'Clear' standard. Writes 0x00 across all logical blocks, flushes OS write caches to disk, and executes cryptographic readback verification.";
        case SanitizationMethod::DOD_5220_22_M:
            return "Standard Department of Defense 5220.22-M 3-pass wipe. Pass 1 writes 0x00, Pass 2 writes 0xFF, and Pass 3 writes cryptographically secure pseudorandom bytes with cache flushes.";
        case SanitizationMethod::PSEUDORANDOM_1_PASS:
            return "Writes a single pass of cryptographically secure random bytes generated from system entropy.";
        case SanitizationMethod::ZERO_FILL:
            return "Writes a single pass of 0x00 zero bytes across the target.";
        default:
            return "Unknown sanitization method.";
    }
}

inline std::vector<std::string> getMethodLimitations(SanitizationMethod method) {
    std::vector<std::string> limits;
    limits.push_back("File-level overwriting cannot alter physical flash blocks remapped by SSD Wear-Leveling / Flash Translation Layer (FTL).");
    limits.push_back("NTFS metadata artifacts ($MFT record residue, USN Journal, and $LogFile entries) may retain file path history until overwritten by filesystem activity.");
    limits.push_back("Cluster slack space (bytes between end of file and end of cluster) may contain unallocated remnants unless free-space wipe is performed.");
    limits.push_back("Volume Shadow Copies (VSS) or automated Windows restore points may contain previous versions of the file.");
    if (method == SanitizationMethod::ZERO_FILL || method == SanitizationMethod::NIST_800_88_CLEAR) {
        limits.push_back("Zero-fill leaves uniform zero-entropy sectors which are obvious to forensic inspectors.");
    }
    return limits;
}

enum class EraseStatus {
    PENDING,
    OVERWRITING,
    VERIFIED,
    COMPLETED,
    BLOCKED_PROTECTED,
    CONFIRMATION_REQUIRED,
    FAILED
};

inline std::ostream& operator<<(std::ostream& os, EraseStatus status) {
    switch (status) {
        case EraseStatus::PENDING:               return os << "PENDING";
        case EraseStatus::OVERWRITING:           return os << "OVERWRITING";
        case EraseStatus::VERIFIED:              return os << "VERIFIED";
        case EraseStatus::COMPLETED:             return os << "COMPLETED";
        case EraseStatus::BLOCKED_PROTECTED:     return os << "BLOCKED_PROTECTED";
        case EraseStatus::CONFIRMATION_REQUIRED: return os << "CONFIRMATION_REQUIRED";
        case EraseStatus::FAILED:                return os << "FAILED";
        default:                                 return os << "UNKNOWN";
    }
}

struct EraseItem {
    std::string path;
    bool is_directory{false};
    uint64_t size_bytes{0};
    EraseStatus status{EraseStatus::PENDING};
    std::string error_message;
};

struct ErasePreview {
    size_t total_files{0};
    size_t total_folders{0};
    uint64_t total_bytes{0};
    SanitizationMethod method{SanitizationMethod::NIST_800_88_CLEAR};
    std::string method_name;
    std::string method_description;
    bool safety_passed{true};
    std::string risk_level; // "Low", "Medium", "High", "PROHIBITED"
    std::vector<EraseItem> items;
    std::vector<std::string> warnings;
    std::vector<std::string> limitations;
};

struct EraseProgress {
    std::string current_file;
    size_t current_file_index{0};
    size_t total_files{0};
    int current_pass{1};
    int total_passes{1};
    uint64_t bytes_processed_file{0};
    uint64_t file_size_bytes{0};
    uint64_t total_bytes_processed{0};
    uint64_t total_bytes_all{0};
    double percentage{0.0};
};

using ProgressCallback = std::function<void(const EraseProgress&)>;

struct VerificationResult {
    bool is_verified{false};
    double match_rate_percentage{0.0}; // 0.0 to 100.0%
    double measured_entropy{0.0};      // 0.0 to 8.0
    bool accessible_after_deletion{false}; // Should be false!
    std::string details;
    std::vector<std::string> limitations;
};

} // namespace sanitization
} // namespace forensivault
