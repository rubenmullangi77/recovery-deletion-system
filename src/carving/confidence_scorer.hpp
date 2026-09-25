#pragma once

#include "carving/file_signature.hpp"
#include <string>
#include <vector>
#include <cstdint>

namespace forensivault::carving {

/**
 * @brief Qualitative confidence level classification.
 */
enum class ConfidenceLevel {
    VeryLow,    // 0 - 39%
    Low,        // 40 - 59%
    Medium,     // 60 - 79%
    High,       // 80 - 94%
    VeryHigh    // 95 - 100%
};

inline std::string confidenceLevelToString(ConfidenceLevel level) {
    switch (level) {
        case ConfidenceLevel::VeryHigh: return "Very High";
        case ConfidenceLevel::High:     return "High";
        case ConfidenceLevel::Medium:   return "Medium";
        case ConfidenceLevel::Low:      return "Low";
        case ConfidenceLevel::VeryLow:  return "Very Low";
        default: return "Unknown";
    }
}

inline std::ostream& operator<<(std::ostream& os, ConfidenceLevel level) {
    return os << confidenceLevelToString(level);
}

inline ConfidenceLevel scoreToConfidenceLevel(int score) {
    if (score >= 95) return ConfidenceLevel::VeryHigh;
    if (score >= 80) return ConfidenceLevel::High;
    if (score >= 60) return ConfidenceLevel::Medium;
    if (score >= 40) return ConfidenceLevel::Low;
    return ConfidenceLevel::VeryLow;
}

/**
 * @brief Detailed breakdown of individual scoring criteria (each 0 to max weight).
 */
struct ConfidenceScoreBreakdown {
    int headerScore{0};        // Max 20: Valid file header & magic bytes
    int footerScore{0};        // Max 20: Valid file footer / EOF delimiter
    int internalStructure{0};  // Max 25: Expected internal chunks, atoms, or tables
    int sizeConsistency{0};    // Max 10: Size within reasonable bounds and matching headers
    int parserValidation{0};   // Max 15: Successful parser traversal without fatal errors
    int checksumValidation{0}; // Max 5:  Checksum/CRC32 verification where applicable
    int metadataScore{0};      // Max 5:  Presence of expected metadata (EXIF, ID3, central dir)
    int penaltyDeductions{0};  // Negative penalties for fragmentation/corruption indicators
    int totalScore{0};          // Clamped to [0, 100]
};

/**
 * @brief Comprehensive, explainable confidence evaluation result.
 */
struct ConfidenceEvaluationResult {
    uint64_t fileId{0};
    std::string fileType;
    uint64_t offset{0};
    uint64_t size{0};
    int confidenceScore{0};             // 0 - 100
    ConfidenceLevel confidenceLevel{ConfidenceLevel::VeryLow};
    std::string validationStatus;       // "VALID", "PARTIAL", "CORRUPTED", "OVERWRITTEN"
    std::vector<std::string> reasons;   // Explanations for awarded points (e.g. "* Valid JPEG header")
    std::vector<std::string> warnings;  // Deductions or missing indicators (e.g. "- Some metadata unavailable")
    ConfidenceScoreBreakdown breakdown;

    // Export to JSON string representation
    std::string toJson() const;
};

/**
 * @brief Multi-factor Recovery Confidence Scorer.
 * Inspects carved byte candidates and applies explainable forensic heuristics.
 */
class RecoveryConfidenceScorer {
public:
    /**
     * @brief Score a carved file candidate.
     * @param fileId Unique identifier of the candidate.
     * @param fileType Format string (e.g. "JPEG", "PNG", "PDF", "ZIP", "DOCX", etc.).
     * @param offset Byte offset in the disk image.
     * @param data Raw carved bytes.
     * @param length Number of bytes in candidate data.
     * @return Fully explainable structured evaluation result.
     */
    static ConfidenceEvaluationResult evaluate(uint64_t fileId,
                                              const std::string& fileType,
                                              uint64_t offset,
                                              const uint8_t* data,
                                              size_t length);

private:
    static void scoreJpeg(const uint8_t* data, size_t length, ConfidenceEvaluationResult& res);
    static void scorePng(const uint8_t* data, size_t length, ConfidenceEvaluationResult& res);
    static void scorePdf(const uint8_t* data, size_t length, ConfidenceEvaluationResult& res);
    static void scoreZipAndOffice(const uint8_t* data, size_t length, const std::string& type, ConfidenceEvaluationResult& res);
    static void scoreMp3(const uint8_t* data, size_t length, ConfidenceEvaluationResult& res);
    static void scoreMp4(const uint8_t* data, size_t length, ConfidenceEvaluationResult& res);
    static void scoreGeneric(const uint8_t* data, size_t length, ConfidenceEvaluationResult& res);

    static void finalizeScore(ConfidenceEvaluationResult& res);
};

} // namespace forensivault::carving
