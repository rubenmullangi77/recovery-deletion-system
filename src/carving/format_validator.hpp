#pragma once

#include "carving/file_signature.hpp"
#include <string>
#include <vector>
#include <cstdint>

namespace forensivault::carving {

/**
 * @brief Detailed format-specific validation result.
 */
struct FormatValidationDetails {
    bool isValid{false};
    std::string validationState{"INVALID"}; // "VALID", "PARTIAL", "INVALID"
    std::string classifiedType;       // e.g., "DOCX" if ZIP contains word/document.xml
    std::string classifiedExtension;  // e.g., "docx"
    std::string classifiedMime;       // e.g., "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    uint64_t trueLength{0};           // Determined exact boundary length
    double confidenceScore{0.0};      // 0 to 100%
    std::string notes;
};

/**
 * @brief Deep structural validator for forensic file carving.
 * Rejects false positives, detects truncation/corruption, and determines exact boundaries.
 */
class FormatValidator {
public:
    /**
     * @brief Validate candidate file data against its expected signature.
     */
    static FormatValidationDetails validate(const FileSignature& sig, 
                                            const uint8_t* data, size_t length);

    // Format-specific deep validators
    static FormatValidationDetails validateJpeg(const uint8_t* data, size_t length);
    static FormatValidationDetails validatePng(const uint8_t* data, size_t length);
    static FormatValidationDetails validatePdf(const uint8_t* data, size_t length);
    static FormatValidationDetails validateZipAndOffice(const uint8_t* data, size_t length);
    static FormatValidationDetails validateMp3(const uint8_t* data, size_t length);
    static FormatValidationDetails validateMp4(const uint8_t* data, size_t length);
};

} // namespace forensivault::carving
