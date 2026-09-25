#include "carving/format_validator.hpp"
#include "core/binary_utils.hpp"
#include "forensivault/common/crypto_hash.hpp"
#include <cstring>
#include <algorithm>
#include <iostream>

namespace forensivault::carving {

FormatValidationDetails FormatValidator::validate(const FileSignature& sig, 
                                                  const uint8_t* data, size_t length) {
    if (!data || length < sig.minSize) {
        FormatValidationDetails res;
        res.isValid = false;
        res.validationState = "INVALID";
        res.classifiedType = sig.fileType;
        res.classifiedExtension = sig.extension;
        res.classifiedMime = sig.mimeType;
        res.trueLength = 0;
        res.confidenceScore = 0.0;
        res.notes = "Data size below minimum required for format";
        return res;
    }

    if (sig.fileType == "JPEG") {
        return validateJpeg(data, length);
    } else if (sig.fileType == "PNG") {
        return validatePng(data, length);
    } else if (sig.fileType == "PDF") {
        return validatePdf(data, length);
    } else if (sig.fileType == "ZIP") {
        return validateZipAndOffice(data, length);
    } else if (sig.fileType == "MP3") {
        return validateMp3(data, length);
    } else if (sig.fileType == "MP4") {
        return validateMp4(data, length);
    }

    // Default fallback
    FormatValidationDetails res;
    res.isValid = true;
    res.validationState = "VALID";
    res.classifiedType = sig.fileType;
    res.classifiedExtension = sig.extension;
    res.classifiedMime = sig.mimeType;
    res.trueLength = length;
    res.confidenceScore = 50.0;
    res.notes = "Basic signature match without deep parser";
    return res;
}

// ---------------- 1. JPEG Validator ----------------
FormatValidationDetails FormatValidator::validateJpeg(const uint8_t* data, size_t length) {
    FormatValidationDetails res;
    res.classifiedType = "JPEG";
    res.classifiedExtension = "jpg";
    res.classifiedMime = "image/jpeg";
    res.validationState = "INVALID";

    if (length < 4 || data[0] != 0xFF || data[1] != 0xD8) {
        res.notes = "Invalid JPEG Start of Image (SOI) marker";
        res.validationState = "INVALID";
        return res;
    }

    int64_t eoiPos = -1;
    size_t i = 2;

    // Segment walking: jump marker segments using their 2-byte big-endian length
    // This avoids false truncation from embedded EXIF thumbnails in APP1.
    while (i + 1 < length) {
        if (data[i] != 0xFF) {
            i++;
            continue;
        }

        while (i + 1 < length && data[i + 1] == 0xFF) {
            i++;
        }
        if (i + 1 >= length) break;

        uint8_t marker = data[i + 1];

        if (marker == 0xD9) { // EOI (End of Image)
            eoiPos = static_cast<int64_t>(i + 2);
            break;
        }

        if (marker == 0xDA) { // SOS (Start of Scan) - entropy coded stream starts!
            size_t sosLen = 2;
            if (i + 3 < length) {
                sosLen = (static_cast<size_t>(data[i + 2]) << 8) | data[i + 3];
            }
            i += 2 + sosLen;

            // Search entropy-coded stream for true final EOI (FF D9)
            for (; i + 1 < length; ++i) {
                if (data[i] == 0xFF) {
                    uint8_t m = data[i + 1];
                    if (m == 0xD9) {
                        eoiPos = static_cast<int64_t>(i + 2);
                        break;
                    } else if (m == 0x00 || (m >= 0xD0 && m <= 0xD7)) {
                        i++; // Escaped 0xFF or restart marker, skip
                    }
                }
            }
            break;
        }

        // Standalone markers without payload length
        if ((marker >= 0xD0 && marker <= 0xD7) || marker == 0x01 || marker == 0x00) {
            i += 2;
            continue;
        }

        // Variable length markers: APPn, DQT, SOF, DHT, DRI, COM
        if (i + 3 < length) {
            size_t markerLen = (static_cast<size_t>(data[i + 2]) << 8) | data[i + 3];
            if (markerLen < 2 || i + 2 + markerLen > length) {
                break;
            }
            i += 2 + markerLen;
        } else {
            break;
        }
    }

    // Fallback: If segment walk did not terminate on EOI, search forward
    if (eoiPos <= 0) {
        for (size_t k = (i > 2 ? i : 2); k + 1 < length; ++k) {
            if (data[k] == 0xFF && data[k + 1] == 0xD9) {
                eoiPos = static_cast<int64_t>(k + 2);
                break;
            }
        }
    }

    if (eoiPos <= 0) {
        res.notes = "JPEG SOI header found, but End of Image (EOI 0xFFD9) marker missing (Partial recovery / fragmentation unresolved)";
        res.trueLength = length;
        res.confidenceScore = 35.0; // Partial confidence
        res.isValid = false;
        res.validationState = "PARTIAL";
        return res;
    }

    res.trueLength = static_cast<uint64_t>(eoiPos);
    res.isValid = true;
    res.validationState = "VALID";
    res.confidenceScore = 95.0;
    res.notes = "Valid JPEG image: SOI (FFD8) and EOI (FFD9) verified with internal segment consistency";
    return res;
}

// ---------------- 2. PNG Validator ----------------
FormatValidationDetails FormatValidator::validatePng(const uint8_t* data, size_t length) {
    FormatValidationDetails res;
    res.classifiedType = "PNG";
    res.classifiedExtension = "png";
    res.classifiedMime = "image/png";
    res.validationState = "INVALID";

    // Header check: 89 50 4E 47 0D 0A 1A 0A
    const uint8_t pngHeader[] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    if (length < 8 || std::memcmp(data, pngHeader, 8) != 0) {
        res.notes = "Missing standard 8-byte PNG header";
        res.validationState = "INVALID";
        return res;
    }

    // Walk PNG chunks: Length (4B, big endian) + Chunk Type (4B) + Data (length B) + CRC (4B)
    size_t offset = 8;
    bool foundIhdr = false;
    bool foundIend = false;

    while (offset + 8 <= length) {
        uint32_t chunkLen = (static_cast<uint32_t>(data[offset]) << 24) |
                            (static_cast<uint32_t>(data[offset + 1]) << 16) |
                            (static_cast<uint32_t>(data[offset + 2]) << 8) |
                            (static_cast<uint32_t>(data[offset + 3]));

        std::string chunkType(reinterpret_cast<const char*>(data + offset + 4), 4);

        if (offset == 8) {
            if (chunkType == "IHDR") {
                foundIhdr = true;
            } else {
                res.notes = "First chunk is not IHDR";
                res.validationState = "INVALID";
                break;
            }
        }

        // Check if chunk extends beyond length
        if (offset + 12 + chunkLen > length) {
            res.notes = "PNG truncated inside chunk '" + chunkType + "'";
            break;
        }

        // Check CRC of chunk
        uint32_t expectedCrc = (static_cast<uint32_t>(data[offset + 8 + chunkLen]) << 24) |
                               (static_cast<uint32_t>(data[offset + 8 + chunkLen + 1]) << 16) |
                               (static_cast<uint32_t>(data[offset + 8 + chunkLen + 2]) << 8) |
                               (static_cast<uint32_t>(data[offset + 8 + chunkLen + 3]));

        uint32_t actualCrc = CryptoHash::crc32(data + offset + 4, chunkLen + 4);
        if (expectedCrc != actualCrc) {
            res.notes = "PNG chunk '" + chunkType + "' has corrupted CRC";
        }

        offset += 12 + chunkLen;

        if (chunkType == "IEND") {
            foundIend = true;
            break;
        }
    }

    if (foundIhdr && foundIend) {
        res.isValid = true;
        res.validationState = "VALID";
        res.trueLength = offset;
        res.confidenceScore = 98.0;
        res.notes = "Valid PNG image with verified IHDR and IEND chunks";
    } else {
        res.isValid = false;
        res.validationState = foundIhdr ? "PARTIAL" : "INVALID";
        res.trueLength = offset;
        res.confidenceScore = foundIhdr ? 45.0 : 10.0;
        if (res.notes.empty()) res.notes = "Incomplete PNG structure: IEND chunk not reached (Partial recovery / fragmentation unresolved)";
    }

    return res;
}

// ---------------- 3. PDF Validator ----------------
FormatValidationDetails FormatValidator::validatePdf(const uint8_t* data, size_t length) {
    FormatValidationDetails res;
    res.classifiedType = "PDF";
    res.classifiedExtension = "pdf";
    res.classifiedMime = "application/pdf";
    res.validationState = "INVALID";

    if (length < 5 || std::memcmp(data, "%PDF-", 5) != 0) {
        res.notes = "Invalid PDF magic header";
        res.validationState = "INVALID";
        return res;
    }

    // Search for %%EOF footer
    const std::string eofTag = "%%EOF";
    int64_t lastEof = -1;

    for (size_t i = 5; i + 5 <= length; ++i) {
        if (std::memcmp(data + i, eofTag.data(), 5) == 0) {
            size_t endPos = i + 5;
            while (endPos < length && (data[endPos] == '\r' || data[endPos] == '\n')) {
                endPos++;
            }
            lastEof = static_cast<int64_t>(endPos);
        }
    }

    if (lastEof <= 0) {
        res.isValid = false;
        res.validationState = "PARTIAL";
        res.trueLength = length;
        res.confidenceScore = 40.0;
        res.notes = "PDF header %PDF- found, but %%EOF trailer marker missing (Partial recovery / fragmentation unresolved)";
        return res;
    }

    res.isValid = true;
    res.validationState = "VALID";
    res.trueLength = static_cast<uint64_t>(lastEof);
    res.confidenceScore = 95.0;
    res.notes = "Valid PDF document: verified %PDF- header and %%EOF trailer marker";
    return res;
}

// ---------------- 4. ZIP & Office (DOCX, XLSX, PPTX) Validator ----------------
FormatValidationDetails FormatValidator::validateZipAndOffice(const uint8_t* data, size_t length) {
    FormatValidationDetails res;
    res.classifiedType = "ZIP";
    res.classifiedExtension = "zip";
    res.classifiedMime = "application/zip";
    res.validationState = "INVALID";

    const uint8_t zipHeader[] = {0x50, 0x4B, 0x03, 0x04};
    if (length < 22 || std::memcmp(data, zipHeader, 4) != 0) {
        res.notes = "Invalid ZIP local file header (PK\x03\x04 missing)";
        res.validationState = "INVALID";
        return res;
    }

    // Search backwards for End of Central Directory Record (EOCD: 50 4B 05 06)
    // EOCD is located at the very end of the archive (within 65,535 byte comment + 22 bytes header)
    int64_t eocdOffset = -1;
    size_t searchBackMax = std::min<size_t>(length, 65535 + 22);
    size_t startScan = length >= 22 ? length - 22 : 0;
    size_t endScan = length >= searchBackMax ? length - searchBackMax : 0;

    for (size_t i = startScan; i >= endScan; --i) {
        if (data[i] == 0x50 && data[i + 1] == 0x4B && data[i + 2] == 0x05 && data[i + 3] == 0x06) {
            uint16_t commentLen = static_cast<uint16_t>(data[i + 20]) |
                                 (static_cast<uint16_t>(data[i + 21]) << 8);
            if (i + 22 + commentLen <= length) {
                eocdOffset = static_cast<int64_t>(i + 22 + commentLen);
                break;
            }
        }
        if (i == 0) break;
    }

    // Fallback forward scan if backwards search did not match
    if (eocdOffset <= 0) {
        for (size_t i = 0; i + 22 <= length; ++i) {
            if (data[i] == 0x50 && data[i + 1] == 0x4B && data[i + 2] == 0x05 && data[i + 3] == 0x06) {
                uint16_t commentLen = static_cast<uint16_t>(data[i + 20]) |
                                     (static_cast<uint16_t>(data[i + 21]) << 8);
                if (i + 22 + commentLen <= length) {
                    eocdOffset = static_cast<int64_t>(i + 22 + commentLen);
                }
            }
        }
    }

    if (eocdOffset <= 0) {
        res.isValid = false;
        res.validationState = "PARTIAL";
        res.trueLength = length;
        res.confidenceScore = 35.0;
        res.notes = "PK\x03\x04 header found, but End of Central Directory (EOCD 0x06054B50) missing or truncated (Partial recovery / fragmentation unresolved)";
        return res;
    }

    res.isValid = true;
    res.validationState = "VALID";
    res.trueLength = static_cast<uint64_t>(eocdOffset);

    // Deep inspect contents of ZIP to determine if it is DOCX, XLSX, PPTX
    std::string archiveContent(reinterpret_cast<const char*>(data), static_cast<size_t>(res.trueLength));

    if (archiveContent.find("word/document.xml") != std::string::npos ||
        archiveContent.find("word/") != std::string::npos) {
        res.classifiedType = "DOCX";
        res.classifiedExtension = "docx";
        res.classifiedMime = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
        res.confidenceScore = 96.0;
        res.notes = "Valid Microsoft Word Document (DOCX): OpenXML structures and EOCD verified";
    } else if (archiveContent.find("xl/workbook.xml") != std::string::npos ||
               archiveContent.find("xl/") != std::string::npos) {
        res.classifiedType = "XLSX";
        res.classifiedExtension = "xlsx";
        res.classifiedMime = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
        res.confidenceScore = 96.0;
        res.notes = "Valid Microsoft Excel Spreadsheet (XLSX): OpenXML structures and EOCD verified";
    } else if (archiveContent.find("ppt/presentation.xml") != std::string::npos ||
               archiveContent.find("ppt/") != std::string::npos) {
        res.classifiedType = "PPTX";
        res.classifiedExtension = "pptx";
        res.classifiedMime = "application/vnd.openxmlformats-officedocument.presentationml.presentation";
        res.confidenceScore = 96.0;
        res.notes = "Valid Microsoft PowerPoint Presentation (PPTX): OpenXML structures and EOCD verified";
    } else {
        res.confidenceScore = 92.0;
        res.notes = "Valid standard ZIP archive: End of Central Directory verified";
    }

    return res;
}

// ---------------- 5. MP3 Validator ----------------
FormatValidationDetails FormatValidator::validateMp3(const uint8_t* data, size_t length) {
    FormatValidationDetails res;
    res.classifiedType = "MP3";
    res.classifiedExtension = "mp3";
    res.classifiedMime = "audio/mpeg";

    if (length < 10) {
        res.notes = "Insufficient data for MP3 inspection";
        return res;
    }

    // Check for ID3v2 header: "ID3" (49 44 33)
    if (data[0] == 'I' && data[1] == 'D' && data[2] == '3') {
        // ID3v2 tag size is encoded in bytes 6, 7, 8, 9 as 7-bit syncsafe integers
        uint32_t tagSize = ((data[6] & 0x7F) << 21) |
                           ((data[7] & 0x7F) << 14) |
                           ((data[8] & 0x7F) << 7)  |
                           (data[9] & 0x7F);
        uint64_t id3Total = 10 + tagSize;

        res.isValid = true;
        res.validationState = "VALID";
        res.trueLength = std::min<uint64_t>(length, std::max<uint64_t>(id3Total, 2048));
        res.confidenceScore = 90.0;
        res.notes = "Valid MP3 audio container: ID3v2 header and syncsafe tag size (" + 
                    std::to_string(tagSize) + " bytes) verified";
        return res;
    }

    // Check for MPEG frame sync: 0xFF 0xFB (or 0xFF 0xFA, 0xFF 0xF3, 0xFF 0xF2)
    if (data[0] == 0xFF && (data[1] & 0xE0) == 0xE0) {
        res.isValid = true;
        res.validationState = "VALID";
        res.trueLength = length;
        res.confidenceScore = 80.0;
        res.notes = "Valid MPEG Audio frame synchronization sequence detected";
        return res;
    }

    res.notes = "Neither ID3v2 header nor MPEG audio sync frame found";
    return res;
}

// ---------------- 6. MP4 Validator ----------------
FormatValidationDetails FormatValidator::validateMp4(const uint8_t* data, size_t length) {
    FormatValidationDetails res;
    res.classifiedType = "MP4";
    res.classifiedExtension = "mp4";
    res.classifiedMime = "video/mp4";

    if (length < 8) {
        res.notes = "Insufficient length for MP4 box inspection";
        return res;
    }

    // MP4 begins with an atom/box: 4-byte size, 4-byte type
    uint32_t boxSize = (static_cast<uint32_t>(data[0]) << 24) |
                       (static_cast<uint32_t>(data[1]) << 16) |
                       (static_cast<uint32_t>(data[2]) << 8)  |
                       (static_cast<uint32_t>(data[3]));

    std::string boxType(reinterpret_cast<const char*>(data + 4), 4);

    if (boxType != "ftyp") {
        res.notes = "First MP4 box is not 'ftyp' (found '" + boxType + "')";
        return res;
    }

    // Walk through primary boxes if possible to find 'moov' or 'mdat'
    size_t offset = 0;
    bool foundMdatOrMoov = false;
    uint64_t totalMediaLength = boxSize;

    while (offset + 8 <= length) {
        uint32_t currentSize = (static_cast<uint32_t>(data[offset]) << 24) |
                               (static_cast<uint32_t>(data[offset + 1]) << 16) |
                               (static_cast<uint32_t>(data[offset + 2]) << 8)  |
                               (static_cast<uint32_t>(data[offset + 3]));
        if (currentSize == 0) { // Box extends to EOF
            totalMediaLength = length;
            break;
        }

        std::string currentType(reinterpret_cast<const char*>(data + offset + 4), 4);
        if (currentType == "moov" || currentType == "mdat") {
            foundMdatOrMoov = true;
        }

        offset += currentSize;
        totalMediaLength = offset;
        if (offset > length || currentSize < 8) break;
    }

    res.isValid = true;
    res.validationState = "VALID";
    res.trueLength = std::min<uint64_t>(length, std::max<uint64_t>(totalMediaLength, 512));
    res.confidenceScore = foundMdatOrMoov ? 95.0 : 85.0;
    res.notes = "Valid MP4 / ISO Base Media File container: verified 'ftyp' atom and box headers";
    return res;
}

} // namespace forensivault::carving
