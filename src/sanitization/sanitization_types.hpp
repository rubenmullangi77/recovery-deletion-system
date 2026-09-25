#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <functional>
#include <ostream>

namespace forensivault {
namespace sanitization {

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
