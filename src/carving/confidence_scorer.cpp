#include "carving/confidence_scorer.hpp"
#include "core/binary_utils.hpp"
#include "forensivault/common/crypto_hash.hpp"
#include <sstream>
#include <iomanip>
#include <cstring>
#include <algorithm>

namespace forensivault::carving {

std::string ConfidenceEvaluationResult::toJson() const {
    std::ostringstream ss;
    ss << "{\n"
       << "  \"file_id\": " << fileId << ",\n"
       << "  \"file_type\": \"" << fileType << "\",\n"
       << "  \"offset\": " << offset << ",\n"
       << "  \"size\": " << size << ",\n"
       << "  \"confidence_score\": " << confidenceScore << ",\n"
       << "  \"confidence_level\": \"" << confidenceLevelToString(confidenceLevel) << "\",\n"
       << "  \"validation_status\": \"" << validationStatus << "\",\n"
       << "  \"reasons\": [\n";
    for (size_t i = 0; i < reasons.size(); ++i) {
        ss << "    \"" << reasons[i] << "\"" << (i + 1 < reasons.size() ? "," : "") << "\n";
    }
    ss << "  ],\n"
       << "  \"warnings\": [\n";
    for (size_t i = 0; i < warnings.size(); ++i) {
        ss << "    \"" << warnings[i] << "\"" << (i + 1 < warnings.size() ? "," : "") << "\n";
    }
    ss << "  ]\n"
       << "}";
    return ss.str();
}

ConfidenceEvaluationResult RecoveryConfidenceScorer::evaluate(uint64_t fileId,
                                                             const std::string& fileType,
                                                             uint64_t offset,
                                                             const uint8_t* data,
                                                             size_t length) {
    ConfidenceEvaluationResult res;
    res.fileId = fileId;
    res.fileType = fileType;
    res.offset = offset;
    res.size = length;

    if (!data || length == 0) {
        res.validationStatus = "CORRUPTED";
        res.warnings.push_back("Null or zero-length candidate payload");
        finalizeScore(res);
        return res;
    }

    if (fileType == "JPEG") {
        scoreJpeg(data, length, res);
    } else if (fileType == "PNG") {
        scorePng(data, length, res);
    } else if (fileType == "PDF") {
        scorePdf(data, length, res);
    } else if (fileType == "ZIP" || fileType == "DOCX" || fileType == "XLSX" || fileType == "PPTX") {
        scoreZipAndOffice(data, length, fileType, res);
    } else if (fileType == "MP3") {
        scoreMp3(data, length, res);
    } else if (fileType == "MP4") {
        scoreMp4(data, length, res);
    } else {
        scoreGeneric(data, length, res);
    }

    finalizeScore(res);
    return res;
}

void RecoveryConfidenceScorer::finalizeScore(ConfidenceEvaluationResult& res) {
    int rawTotal = res.breakdown.headerScore +
                   res.breakdown.footerScore +
                   res.breakdown.internalStructure +
                   res.breakdown.sizeConsistency +
                   res.breakdown.parserValidation +
                   res.breakdown.checksumValidation +
                   res.breakdown.metadataScore -
                   res.breakdown.penaltyDeductions;

    res.confidenceScore = std::clamp(rawTotal, 0, 100);
    res.breakdown.totalScore = res.confidenceScore;
    res.confidenceLevel = scoreToConfidenceLevel(res.confidenceScore);

    if (res.confidenceScore >= 80) {
        res.validationStatus = "VALID";
    } else if (res.confidenceScore >= 40) {
        res.validationStatus = "PARTIAL";
    } else {
        res.validationStatus = "CORRUPTED";
    }
}

// ---------------- 1. JPEG Scoring ----------------
void RecoveryConfidenceScorer::scoreJpeg(const uint8_t* data, size_t length, ConfidenceEvaluationResult& res) {
    // Header check: 0xFF 0xD8 0xFF (Max 20 pts)
    if (length >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF) {
        res.breakdown.headerScore = 20;
        res.reasons.push_back("Valid JPEG SOI (0xFFD8) start marker");
    } else {
        res.warnings.push_back("Missing standard JPEG SOI header");
    }

    // Footer check: 0xFF 0xD9 (Max 20 pts)
    if (length >= 2 && data[length - 2] == 0xFF && data[length - 1] == 0xD9) {
        res.breakdown.footerScore = 20;
        res.reasons.push_back("Valid JPEG EOI (0xFFD9) end marker");
    } else {
        res.warnings.push_back("Missing JPEG EOI end marker (possible truncation or fragmentation)");
        res.breakdown.penaltyDeductions += 15;
    }

    // Internal structure: Scan segments (SOF0, DQT, DHT, SOS) (Max 25 pts)
    bool hasDqt = false;
    bool hasSof = false;
    bool hasSos = false;
    bool hasAppMarker = false;

    for (size_t i = 2; i + 1 < length; ++i) {
        if (data[i] == 0xFF) {
            uint8_t marker = data[i + 1];
            if (marker >= 0xE0 && marker <= 0xEF) hasAppMarker = true; // APP0 (JFIF) or APP1 (EXIF)
            if (marker == 0xDB) hasDqt = true; // Define Quantization Table
            if (marker == 0xC0 || marker == 0xC2) hasSof = true; // Start of Frame
            if (marker == 0xDA) hasSos = true; // Start of Scan
        }
    }

    if (hasSof && hasSos) {
        res.breakdown.internalStructure = 25;
        res.reasons.push_back(hasDqt 
            ? "Valid JPEG frame, quantization tables (DQT), and scan structure verified"
            : "Valid JPEG frame and scan structure (SOF and SOS segments present)");
    } else if (hasSos || hasSof) {
        res.breakdown.internalStructure = 15;
        res.reasons.push_back("Partial JPEG structure identified");
    } else {
        res.warnings.push_back("Missing critical JPEG SOF/SOS segment tables");
        res.breakdown.penaltyDeductions += 10;
    }

    // Size consistency (Max 10 pts)
    if (length >= 100 && length <= 50 * 1024 * 1024) {
        res.breakdown.sizeConsistency = 10;
        res.reasons.push_back("File size is consistent with standard photographic images");
    }

    // Parser validation (Max 15 pts)
    if (res.breakdown.headerScore > 0 && res.breakdown.internalStructure >= 15) {
        res.breakdown.parserValidation = 15;
        res.reasons.push_back("Structural parser completed without fatal syntax errors");
    }

    // Metadata presence (Max 5 pts)
    if (hasAppMarker) {
        res.breakdown.metadataScore = 5;
        res.reasons.push_back("JFIF or EXIF application metadata header present");
    } else {
        res.warnings.push_back("Some metadata unavailable (no standard JFIF/EXIF APP header)");
    }
}

// ---------------- 2. PNG Scoring ----------------
void RecoveryConfidenceScorer::scorePng(const uint8_t* data, size_t length, ConfidenceEvaluationResult& res) {
    const uint8_t pngHeader[] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    if (length >= 8 && std::memcmp(data, pngHeader, 8) == 0) {
        res.breakdown.headerScore = 20;
        res.reasons.push_back("Valid PNG 8-byte magic header (89 50 4E 47 0D 0A 1A 0A)");
    } else {
        res.warnings.push_back("Invalid PNG header signature");
    }

    // Walk chunks
    size_t offset = 8;
    bool hasIhdr = false;
    bool hasIdat = false;
    bool hasIend = false;
    bool crcFailed = false;

    while (offset + 12 <= length) {
        uint32_t chunkLen = (static_cast<uint32_t>(data[offset]) << 24) |
                            (static_cast<uint32_t>(data[offset + 1]) << 16) |
                            (static_cast<uint32_t>(data[offset + 2]) << 8) |
                            (static_cast<uint32_t>(data[offset + 3]));

        std::string type(reinterpret_cast<const char*>(data + offset + 4), 4);
        if (type == "IHDR") hasIhdr = true;
        if (type == "IDAT") hasIdat = true;
        if (type == "IEND") hasIend = true;

        if (offset + 12 + chunkLen <= length) {
            uint32_t expectedCrc = (static_cast<uint32_t>(data[offset + 8 + chunkLen]) << 24) |
                                   (static_cast<uint32_t>(data[offset + 8 + chunkLen + 1]) << 16) |
                                   (static_cast<uint32_t>(data[offset + 8 + chunkLen + 2]) << 8) |
                                   (static_cast<uint32_t>(data[offset + 8 + chunkLen + 3]));
            uint32_t actualCrc = CryptoHash::crc32(data + offset + 4, chunkLen + 4);
            if (expectedCrc != actualCrc) {
                crcFailed = true;
            }
        }

        offset += 12 + chunkLen;
        if (type == "IEND" || offset > length) break;
    }

    if (hasIend) {
        res.breakdown.footerScore = 20;
        res.reasons.push_back("Valid PNG IEND terminating chunk verified");
    } else {
        res.warnings.push_back("Missing PNG IEND chunk (image is truncated or fragmented)");
        res.breakdown.penaltyDeductions += 15;
    }

    if (hasIhdr && hasIdat) {
        res.breakdown.internalStructure = 25;
        res.reasons.push_back("Expected PNG internal structure (IHDR and IDAT chunks present)");
    } else if (hasIhdr) {
        res.breakdown.internalStructure = 15;
        res.reasons.push_back("Valid IHDR chunk found");
    }

    // CRC validation (Max 5 pts)
    if (!crcFailed && (hasIhdr || hasIend)) {
        res.breakdown.checksumValidation = 5;
        res.reasons.push_back("PNG chunk CRC32 checksums verified successfully");
    } else if (crcFailed) {
        res.warnings.push_back("CRC32 mismatch detected in one or more PNG chunks");
        res.breakdown.penaltyDeductions += 15;
    }

    // Size consistency & parser (Max 10 + 15 pts)
    if (length >= 45 && length <= 100 * 1024 * 1024) {
        res.breakdown.sizeConsistency = 10;
        res.reasons.push_back("File length matches chunk sequence total");
    }
    if (hasIhdr && hasIend && !crcFailed) {
        res.breakdown.parserValidation = 15;
        res.breakdown.metadataScore = 5;
        res.reasons.push_back("PNG chunk parser successfully reached clean termination");
    }
}

// ---------------- 3. PDF Scoring ----------------
void RecoveryConfidenceScorer::scorePdf(const uint8_t* data, size_t length, ConfidenceEvaluationResult& res) {
    if (length >= 5 && std::memcmp(data, "%PDF-", 5) == 0) {
        res.breakdown.headerScore = 20;
        res.reasons.push_back("Valid %PDF- version banner");
    } else {
        res.warnings.push_back("Missing %PDF- header");
    }

    std::string text(reinterpret_cast<const char*>(data), length);

    // Footer: %%EOF
    if (text.rfind("%%EOF") != std::string::npos) {
        res.breakdown.footerScore = 20;
        res.reasons.push_back("Valid %%EOF trailer marker found");
    } else {
        res.warnings.push_back("Missing %%EOF trailer marker (file truncated or unclosed)");
        res.breakdown.penaltyDeductions += 20;
    }

    // Internal structure: objects, xref, trailer
    bool hasObj = (text.find(" obj") != std::string::npos);
    bool hasXref = (text.find("xref") != std::string::npos);
    bool hasTrailer = (text.find("trailer") != std::string::npos);

    if (hasObj && hasXref && hasTrailer) {
        res.breakdown.internalStructure = 25;
        res.reasons.push_back("Expected PDF internal structure (objects, xref table, trailer present)");
    } else if (hasObj) {
        res.breakdown.internalStructure = 15;
        res.reasons.push_back("PDF object definitions located");
    } else {
        res.warnings.push_back("PDF lacks object dictionary definitions");
        res.breakdown.penaltyDeductions += 10;
    }

    if (length >= 100 && length <= 500 * 1024 * 1024) {
        res.breakdown.sizeConsistency = 10;
        res.reasons.push_back("Document size is consistent with standard PDF bounds");
    }

    if (hasObj && text.rfind("%%EOF") != std::string::npos) {
        res.breakdown.parserValidation = 15;
        res.breakdown.metadataScore = 5;
        res.reasons.push_back("PDF cross-reference and object tree successfully traversed");
    }
}

// ---------------- 4. ZIP & Office Scoring ----------------
void RecoveryConfidenceScorer::scoreZipAndOffice(const uint8_t* data, size_t length, 
                                                const std::string& type, ConfidenceEvaluationResult& res) {
    if (length >= 4 && data[0] == 0x50 && data[1] == 0x4B && data[2] == 0x03 && data[3] == 0x04) {
        res.breakdown.headerScore = 20;
        res.reasons.push_back("Valid PK\\x03\\x04 local file header signature");
    } else {
        res.warnings.push_back("Missing PK\\x03\\x04 ZIP magic header");
    }

    // Look for End of Central Directory (EOCD: 50 4B 05 06)
    bool hasEocd = false;
    for (size_t i = 0; i + 4 <= length; ++i) {
        if (data[i] == 0x50 && data[i + 1] == 0x4B && data[i + 2] == 0x05 && data[i + 3] == 0x06) {
            hasEocd = true;
            break;
        }
    }

    if (hasEocd) {
        res.breakdown.footerScore = 20;
        res.reasons.push_back("Valid End of Central Directory Record (EOCD) verified");
    } else {
        res.warnings.push_back("Missing End of Central Directory Record (archive truncated or corrupted)");
        res.breakdown.penaltyDeductions += 25;
    }

    // Look for Central Directory file headers (PK 01 02)
    bool hasCentralDir = false;
    for (size_t i = 0; i + 4 <= length; ++i) {
        if (data[i] == 0x50 && data[i + 1] == 0x4B && data[i + 2] == 0x01 && data[i + 3] == 0x02) {
            hasCentralDir = true;
            break;
        }
    }

    if (hasCentralDir) {
        res.breakdown.internalStructure = 25;
        res.reasons.push_back("Central Directory file table entries verified");
    } else {
        res.breakdown.internalStructure = 10;
        res.warnings.push_back("Central directory header missing (possible single-stream or partial archive)");
    }

    // Check OpenXML structures if Office type
    std::string content(reinterpret_cast<const char*>(data), length);
    if (type == "DOCX") {
        if (content.find("word/document.xml") != std::string::npos) {
            res.breakdown.metadataScore = 5;
            res.reasons.push_back("OpenXML WordprocessingML metadata and document tree confirmed");
        } else {
            res.warnings.push_back("DOCX marker word/document.xml missing");
        }
    } else if (type == "XLSX") {
        if (content.find("xl/workbook.xml") != std::string::npos) {
            res.breakdown.metadataScore = 5;
            res.reasons.push_back("OpenXML SpreadsheetML workbook structure confirmed");
        }
    } else if (type == "PPTX") {
        if (content.find("ppt/presentation.xml") != std::string::npos) {
            res.breakdown.metadataScore = 5;
            res.reasons.push_back("OpenXML PresentationML presentation structure confirmed");
        }
    } else {
        res.breakdown.metadataScore = 5;
        res.reasons.push_back("Archive contains valid compression directory metadata");
    }

    if (length >= 22 && length <= 500 * 1024 * 1024) {
        res.breakdown.sizeConsistency = 10;
        res.reasons.push_back("Archive size conforms to standard package constraints");
    }

    if (hasEocd && res.breakdown.headerScore > 0) {
        res.breakdown.parserValidation = 15;
        res.reasons.push_back("ZIP archive directory successfully parsed without decompression faults");
    }
}

// ---------------- 5. MP3 Scoring ----------------
void RecoveryConfidenceScorer::scoreMp3(const uint8_t* data, size_t length, ConfidenceEvaluationResult& res) {
    bool hasId3 = (length >= 3 && data[0] == 'I' && data[1] == 'D' && data[2] == '3');
    bool hasSyncFrame = (length >= 2 && data[0] == 0xFF && (data[1] & 0xE0) == 0xE0);

    if (hasId3) {
        res.breakdown.headerScore = 20;
        res.reasons.push_back("Valid ID3v2 audio metadata tag header");
    } else if (hasSyncFrame) {
        res.breakdown.headerScore = 15;
        res.reasons.push_back("MPEG-1/2 Audio Layer III sync frame header located");
    } else {
        res.warnings.push_back("No standard ID3 header or MPEG sync frame");
    }

    // Search for audio frames throughout payload
    size_t frameCount = 0;
    for (size_t i = 0; i + 1 < length; ++i) {
        if (data[i] == 0xFF && (data[i + 1] & 0xE0) == 0xE0) {
            frameCount++;
        }
    }

    if (frameCount >= 2) {
        res.breakdown.internalStructure = 25;
        res.reasons.push_back("Multiple contiguous MPEG audio sync frames detected");
    } else {
        res.breakdown.internalStructure = 10;
        res.warnings.push_back("Few MPEG sync frames identified");
    }

    if (hasId3) {
        res.breakdown.metadataScore = 5;
        res.reasons.push_back("ID3 tag metadata present");
    }

    if (length >= 512) {
        res.breakdown.sizeConsistency = 10;
        res.breakdown.parserValidation = 15;
        res.reasons.push_back("Audio stream length is within expected audio track parameters");
    }
}

// ---------------- 6. MP4 Scoring ----------------
void RecoveryConfidenceScorer::scoreMp4(const uint8_t* data, size_t length, ConfidenceEvaluationResult& res) {
    if (length >= 8 && data[4] == 'f' && data[5] == 't' && data[6] == 'y' && data[7] == 'p') {
        res.breakdown.headerScore = 20;
        res.reasons.push_back("Valid MP4 'ftyp' container atom header");
    } else {
        res.warnings.push_back("Missing MP4 'ftyp' atom header");
    }

    // Walk atoms
    size_t offset = 0;
    bool hasMoov = false;
    bool hasMdat = false;

    while (offset + 8 <= length) {
        uint32_t boxSize = (static_cast<uint32_t>(data[offset]) << 24) |
                           (static_cast<uint32_t>(data[offset + 1]) << 16) |
                           (static_cast<uint32_t>(data[offset + 2]) << 8) |
                           (static_cast<uint32_t>(data[offset + 3]));
        if (boxSize == 0) break;

        std::string type(reinterpret_cast<const char*>(data + offset + 4), 4);
        if (type == "moov") hasMoov = true;
        if (type == "mdat") hasMdat = true;

        offset += boxSize;
        if (offset > length || boxSize < 8) break;
    }

    if (hasMoov && hasMdat) {
        res.breakdown.internalStructure = 25;
        res.reasons.push_back("Both 'moov' (metadata) and 'mdat' (media payload) boxes confirmed");
    } else if (hasMoov || hasMdat) {
        res.breakdown.internalStructure = 15;
        res.reasons.push_back("Essential media box located");
    }

    if (length >= 512) {
        res.breakdown.sizeConsistency = 10;
        res.breakdown.parserValidation = 15;
        res.reasons.push_back("ISO Base Media File container verified");
    }
}

// ---------------- 7. Generic Fallback Scoring ----------------
void RecoveryConfidenceScorer::scoreGeneric(const uint8_t* data, size_t length, ConfidenceEvaluationResult& res) {
    if (data && length > 0) {
        res.breakdown.headerScore = 15;
        res.reasons.push_back("Signature header match confirmed");
        res.breakdown.sizeConsistency = 10;
        res.reasons.push_back("Candidate length within configured constraints");
        res.warnings.push_back("No specialized format parser available for generic payload");
    }
}

} // namespace forensivault::carving
