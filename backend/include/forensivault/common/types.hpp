#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <chrono>
#include <optional>

namespace forensivault {

// Sector and byte sizing constants
constexpr uint64_t DEFAULT_SECTOR_SIZE = 512;
constexpr uint64_t DEFAULT_CLUSTER_SIZE = 4096;
constexpr uint64_t MAX_CARVE_SIZE = 100ULL * 1024ULL * 1024ULL; // 100 MB default boundary

using ByteBuffer = std::vector<uint8_t>;
using SectorOffset = uint64_t;
using ByteOffset = uint64_t;

// File format categories recognized by the carving engine
enum class FileFormat {
    Unknown,
    JPEG,
    PNG,
    PDF,
    ZIP,        // Also covers DOCX, XLSX, PPTX, APK, JAR
    MP4,
    SQLITE,
    PE_EXE,
    GIF,
    RIFF_WAV_AVI
};

inline std::string fileFormatToString(FileFormat fmt) {
    switch (fmt) {
        case FileFormat::JPEG: return "JPEG";
        case FileFormat::PNG: return "PNG";
        case FileFormat::PDF: return "PDF";
        case FileFormat::ZIP: return "ZIP";
        case FileFormat::MP4: return "MP4";
        case FileFormat::SQLITE: return "SQLite";
        case FileFormat::PE_EXE: return "PE Executable";
        case FileFormat::GIF: return "GIF";
        case FileFormat::RIFF_WAV_AVI: return "RIFF (WAV/AVI)";
        default: return "Unknown";
    }
}

// Forensic status of an analyzed or recovered file
enum class ForensicFileStatus {
    IntactFilesystem,   // Preserved directory entry and cluster chain
    CarvedComplete,     // Recovered via signature matching with valid end-of-file & internal structure
    CarvedPartial,      // Header found, but truncated, missing footer, or fragmented
    Corrupted,          // Signature found, but internal structural parsing failed
    Overwritten         // Sectors have been overwritten; mathematically unrecoverable
};

inline std::string fileStatusToString(ForensicFileStatus status) {
    switch (status) {
        case ForensicFileStatus::IntactFilesystem: return "Intact (Filesystem)";
        case ForensicFileStatus::CarvedComplete:   return "Carved (Complete)";
        case ForensicFileStatus::CarvedPartial:    return "Carved (Partial / Fragmented)";
        case ForensicFileStatus::Corrupted:        return "Corrupted Structure";
        case ForensicFileStatus::Overwritten:      return "Overwritten (Unrecoverable)";
        default: return "Unknown";
    }
}

// Structural validation result from format parsers
struct ValidationResult {
    bool isValid{false};
    bool hasValidHeader{false};
    bool hasValidFooter{false};
    bool hasValidInternalStructure{false};
    double calculatedEntropy{0.0};
    uint64_t validatedLength{0};
    std::string diagnosticMessage;
};

// Confidence assessment breakdown for forensic reporting
struct ConfidenceBreakdown {
    int headerMatchWeight{0};       // Exact magic byte match (up to 25 pts)
    int footerMatchWeight{0};       // Clean EOF delimiter (up to 25 pts)
    int structureParseWeight{0};    // Valid internal chunks/markers (up to 30 pts)
    int entropyWeight{0};           // Realistic data entropy profile (up to 20 pts)
    int totalScore{0};              // 0 to 100%
    std::vector<std::string> forensicEvidenceTags;
};

// Represents a file identified during forensic carving or filesystem analysis
struct CarvedFile {
    uint64_t id{0};
    FileFormat format{FileFormat::Unknown};
    ForensicFileStatus status{ForensicFileStatus::CarvedPartial};
    ByteOffset startOffset{0};
    uint64_t lengthBytes{0};
    SectorOffset startSector{0};
    SectorOffset sectorCount{0};
    std::string detectedExtension;
    std::string sha256Hash;
    std::string md5Hash;
    ConfidenceBreakdown confidence;
    bool isFragmented{false};
    std::string suggestedFilename;
};

// Supported sanitization standards
enum class SanitizationMethod {
    ZeroFill,           // Single pass: 0x00
    RandomFill,         // Single pass: Cryptographic pseudo-random bytes
    NIST_800_88_Clear,  // NIST SP 800-88 Rev 1 Clear: Single pass overwrite (zeros or pseudo-random) + verification
    NIST_800_88_Purge,  // NIST SP 800-88 Rev 1 Purge: 3-pass overwrite + invert + random + verification
    DoD_5220_22_M_3Pass,// DoD 5220.22-M: Pass 1 (zeros), Pass 2 (ones), Pass 3 (random) + verify
    DoD_5220_22_M_7Pass // DoD 5220.22-M ECE: 7 passes with alternating patterns + verify
};

inline std::string sanitizationMethodToString(SanitizationMethod method) {
    switch (method) {
        case SanitizationMethod::ZeroFill:            return "Zero-Fill (1-Pass)";
        case SanitizationMethod::RandomFill:          return "Random-Fill (1-Pass)";
        case SanitizationMethod::NIST_800_88_Clear:   return "NIST SP 800-88 Rev 1 (Clear)";
        case SanitizationMethod::NIST_800_88_Purge:   return "NIST SP 800-88 Rev 1 (Purge)";
        case SanitizationMethod::DoD_5220_22_M_3Pass: return "DoD 5220.22-M (3-Pass)";
        case SanitizationMethod::DoD_5220_22_M_7Pass: return "DoD 5220.22-M ECE (7-Pass)";
        default: return "Unknown";
    }
}

// Sanitization execution report
struct SanitizationResult {
    bool success{false};
    std::string targetPath;
    SanitizationMethod method{SanitizationMethod::ZeroFill};
    uint64_t totalBytesSanitized{0};
    uint32_t passesCompleted{0};
    bool verificationPassed{false};
    std::string initialHash;
    std::string postWipeHash;
    double residualEntropy{0.0};
    std::chrono::system_clock::time_point timestamp;
    std::string certificateId;
    std::string notes;
};

// Cryptographically chained audit log entry
struct AuditEntry {
    uint64_t index{0};
    std::string timestampIso;
    std::string actionType;
    std::string operatorId;
    std::string targetIdentifier;
    std::string actionDetails;
    std::string previousEntryHash;
    std::string entryHash; // SHA-256(index + timestamp + actionType + operatorId + targetIdentifier + details + prevHash)
};

} // namespace forensivault
