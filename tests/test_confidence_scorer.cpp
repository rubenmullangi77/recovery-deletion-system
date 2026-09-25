#include "test_framework.hpp"
#include "carving/confidence_scorer.hpp"
#include "carving/format_validator.hpp"
#include <vector>
#include <string>
#include <iostream>

using namespace forensivault::carving;

FV_TEST(ConfidenceScorer, QualitativeLevelMappings) {
    ASSERT_EQ(scoreToConfidenceLevel(100), ConfidenceLevel::VeryHigh);
    ASSERT_EQ(scoreToConfidenceLevel(95),  ConfidenceLevel::VeryHigh);
    ASSERT_EQ(scoreToConfidenceLevel(94),  ConfidenceLevel::High);
    ASSERT_EQ(scoreToConfidenceLevel(80),  ConfidenceLevel::High);
    ASSERT_EQ(scoreToConfidenceLevel(79),  ConfidenceLevel::Medium);
    ASSERT_EQ(scoreToConfidenceLevel(60),  ConfidenceLevel::Medium);
    ASSERT_EQ(scoreToConfidenceLevel(59),  ConfidenceLevel::Low);
    ASSERT_EQ(scoreToConfidenceLevel(40),  ConfidenceLevel::Low);
    ASSERT_EQ(scoreToConfidenceLevel(39),  ConfidenceLevel::VeryLow);
    ASSERT_EQ(scoreToConfidenceLevel(0),   ConfidenceLevel::VeryLow);

    ASSERT_EQ(confidenceLevelToString(ConfidenceLevel::VeryHigh), "Very High");
    ASSERT_EQ(confidenceLevelToString(ConfidenceLevel::High),     "High");
    ASSERT_EQ(confidenceLevelToString(ConfidenceLevel::Medium),   "Medium");
    ASSERT_EQ(confidenceLevelToString(ConfidenceLevel::Low),      "Low");
    ASSERT_EQ(confidenceLevelToString(ConfidenceLevel::VeryLow),  "Very Low");
}

FV_TEST(ConfidenceScorer, JpegExplainableScore) {
    // Construct a valid JPEG image payload
    std::vector<uint8_t> validJpeg = {
        0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00, 0x01, 0x01, 0x01, 0x00, 0x60,
        0x00, 0x60, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43, 0x00,
        // SOF0 (Start of Frame)
        0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x11, 0x00,
        // SOS (Start of Scan)
        0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00,
        // Scan data
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x11, 0x22, 0x33,
        // EOI (End of Image)
        0xFF, 0xD9
    };
    // Pad to 120 bytes for realistic size
    validJpeg.resize(120, 0x55);
    validJpeg[118] = 0xFF;
    validJpeg[119] = 0xD9;

    auto eval = RecoveryConfidenceScorer::evaluate(101, "JPEG", 0x1000, validJpeg.data(), validJpeg.size());

    ASSERT_EQ(eval.fileId, 101ULL);
    ASSERT_EQ(eval.fileType, "JPEG");
    ASSERT_EQ(eval.offset, 0x1000ULL);
    ASSERT_EQ(eval.size, validJpeg.size());
    ASSERT_TRUE(eval.confidenceScore >= 95);
    ASSERT_EQ(eval.confidenceLevel, ConfidenceLevel::VeryHigh);
    ASSERT_EQ(eval.validationStatus, "VALID");

    // Must have explainable reasons
    ASSERT_FALSE(eval.reasons.empty());
    bool foundHeaderReason = false;
    bool foundFooterReason = false;
    for (const auto& r : eval.reasons) {
        if (r.find("SOI") != std::string::npos) foundHeaderReason = true;
        if (r.find("EOI") != std::string::npos) foundFooterReason = true;
    }
    ASSERT_TRUE(foundHeaderReason);
    ASSERT_TRUE(foundFooterReason);

    // JSON export check
    std::string json = eval.toJson();
    ASSERT_TRUE(json.find("\"file_id\": 101") != std::string::npos);
    ASSERT_TRUE(json.find("\"confidence_level\": \"Very High\"") != std::string::npos);
}

FV_TEST(ConfidenceScorer, TruncatedJpegPenaltiesAndWarnings) {
    // Truncated JPEG (header present, but missing EOI)
    std::vector<uint8_t> truncJpeg = {
        0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00, 0x01,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
    };

    auto eval = RecoveryConfidenceScorer::evaluate(102, "JPEG", 0x2000, truncJpeg.data(), truncJpeg.size());

    // Score must be significantly penalized due to missing EOI and truncated structure
    ASSERT_TRUE(eval.confidenceScore < 60);
    ASSERT_TRUE(eval.confidenceLevel == ConfidenceLevel::Low || eval.confidenceLevel == ConfidenceLevel::VeryLow);

    // Must produce explicit warnings
    ASSERT_FALSE(eval.warnings.empty());
    bool foundEoiWarning = false;
    for (const auto& w : eval.warnings) {
        if (w.find("EOI") != std::string::npos) foundEoiWarning = true;
    }
    ASSERT_TRUE(foundEoiWarning);
}

FV_TEST(ConfidenceScorer, PngChecksumVerification) {
    // Full minimal valid PNG with IHDR, IDAT, and IEND chunks (70 bytes)
    std::vector<uint8_t> validPng = {
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
        0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4, 0x89,
        0x00, 0x00, 0x00, 0x0D, 0x49, 0x44, 0x41, 0x54,
        0x78, 0x9C, 0x63, 0xF8, 0xCF, 0xC0, 0xF0, 0x1F,
        0x00, 0x05, 0x00, 0x01, 0xFF, 0x89, 0x99, 0x3D, 0x1D,
        0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44,
        0xAE, 0x42, 0x60, 0x82
    };

    auto eval = RecoveryConfidenceScorer::evaluate(103, "PNG", 0x3000, validPng.data(), validPng.size());
    ASSERT_TRUE(eval.confidenceScore >= 95);
    ASSERT_EQ(eval.confidenceLevel, ConfidenceLevel::VeryHigh);
    ASSERT_EQ(eval.breakdown.checksumValidation, 5);

    // Now corrupt one CRC byte
    validPng[validPng.size() - 1] ^= 0xFF;
    auto corruptedEval = RecoveryConfidenceScorer::evaluate(104, "PNG", 0x3000, validPng.data(), validPng.size());
    ASSERT_TRUE(corruptedEval.confidenceScore < eval.confidenceScore);
    bool foundCrcWarning = false;
    for (const auto& w : corruptedEval.warnings) {
        if (w.find("CRC32") != std::string::npos) foundCrcWarning = true;
    }
    ASSERT_TRUE(foundCrcWarning);
}
