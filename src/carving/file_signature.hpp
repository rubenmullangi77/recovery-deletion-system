#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include <optional>

namespace forensivault::carving {

/**
 * @brief Strategy used to extract and bound carved files.
 */
enum class CarvingStrategy {
    HeaderFooter,       // Delimited by distinct header and footer bytes (e.g. JPEG, PDF, PNG)
    LengthInHeader,     // Length or chunk dimensions encoded in header (e.g. PNG chunks, MP4 boxes)
    EmbeddedStructures, // Traversed via internal directory records (e.g. ZIP Central Directory, DOCX/XLSX/PPTX)
    FrameBased          // Sequence of sync frames or tags (e.g. MP3 ID3 / MPEG audio frames)
};

inline std::string carvingStrategyToString(CarvingStrategy strategy) {
    switch (strategy) {
        case CarvingStrategy::HeaderFooter:       return "HeaderFooter";
        case CarvingStrategy::LengthInHeader:     return "LengthInHeader";
        case CarvingStrategy::EmbeddedStructures: return "EmbeddedStructures";
        case CarvingStrategy::FrameBased:         return "FrameBased";
        default: return "Unknown";
    }
}

/**
 * @brief Formal file signature definition for forensic carving.
 */
struct FileSignature {
    std::string fileType;               // e.g. "JPEG", "PNG", "PDF", "ZIP", "DOCX", etc.
    std::string extension;              // e.g. "jpg", "png", "pdf", "zip", "docx"
    std::string mimeType;               // e.g. "image/jpeg", "application/pdf"
    std::vector<uint8_t> header;        // Magic bytes at start
    std::vector<uint8_t> headerMask;    // Optional bitmask (empty means all 0xFF)
    std::vector<uint8_t> footer;        // Magic bytes at end (empty if not applicable)
    uint64_t minSize;                   // Minimum valid byte size
    uint64_t maxReasonableSize;         // Maximum reasonable search boundary
    CarvingStrategy strategy;           // Extraction & boundary resolution algorithm
    int priority{0};                    // Resolution priority (higher priority matched first, e.g. DOCX before ZIP)
};

/**
 * @brief Represents a carved file candidate with forensic metrics.
 */
struct CarvedFile {
    uint64_t id{0};
    std::string fileType;
    std::string extension;
    std::string mimeType;
    uint64_t startOffset{0};
    uint64_t lengthBytes{0};
    uint64_t startSector{0};
    uint64_t sectorSpan{0};
    bool hasValidHeader{false};
    bool hasValidFooter{false};
    bool isValid{false};               // Validated via format-specific structure parser
    double confidenceScore{0.0};       // 0.0 to 100.0%
    std::string confidenceLevel;       // "Very High", "High", "Medium", "Low", "Very Low"
    std::string validationNotes;
    std::string validationState{"INVALID"}; // "VALID", "PARTIAL", "INVALID"
    std::string recoveryMethod{"Raw Signature Carving"};
    std::vector<std::string> reasons;
    std::vector<std::string> warnings;
    std::string sha256;
    std::string recoveredFilePath;
};

/**
 * @brief Signature database holding curated forensic file signatures.
 */
class SignatureDatabase {
public:
    static SignatureDatabase& getInstance();

    SignatureDatabase();

    const std::vector<FileSignature>& getSignatures() const {
        return signatures_;
    }

    void addSignature(const FileSignature& sig);

    /**
     * @brief Finds matching signature for a given header slice.
     */
    std::vector<const FileSignature*> matchHeader(const uint8_t* data, size_t length) const;

private:
    void initializeDefaultSignatures();
    std::vector<FileSignature> signatures_;
};

} // namespace forensivault::carving
