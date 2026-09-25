#include "carving/file_signature.hpp"
#include "core/binary_utils.hpp"
#include <algorithm>

namespace forensivault::carving {

SignatureDatabase& SignatureDatabase::getInstance() {
    static SignatureDatabase instance;
    return instance;
}

SignatureDatabase::SignatureDatabase() {
    initializeDefaultSignatures();
}

void SignatureDatabase::addSignature(const FileSignature& sig) {
    signatures_.push_back(sig);
    // Sort by priority descending (e.g. DOCX/Office before generic ZIP)
    std::sort(signatures_.begin(), signatures_.end(), [](const FileSignature& a, const FileSignature& b) {
        return a.priority > b.priority;
    });
}

void SignatureDatabase::initializeDefaultSignatures() {
    signatures_.clear();

    // 1. JPEG (Joint Photographic Experts Group)
    // Header: FF D8 FF (SOI marker followed by APP0, APP1, or Quantization tables)
    // Footer: FF D9 (EOI marker)
    signatures_.push_back({
        "JPEG",
        "jpg",
        "image/jpeg",
        {0xFF, 0xD8, 0xFF},
        {},
        {0xFF, 0xD9},
        64,                          // Min 64 bytes
        50ULL * 1024ULL * 1024ULL,   // Max 50 MB
        CarvingStrategy::HeaderFooter,
        10
    });

    // 2. PNG (Portable Network Graphics)
    // Header: 89 50 4E 47 0D 0A 1A 0A
    // Footer: 49 45 4E 44 AE 42 60 82 (IEND chunk + CRC)
    signatures_.push_back({
        "PNG",
        "png",
        "image/png",
        {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
        {},
        {0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82},
        45,                          // Min 45 bytes (IHDR + IEND)
        100ULL * 1024ULL * 1024ULL,  // Max 100 MB
        CarvingStrategy::LengthInHeader, // We can validate both chunk lengths and IEND footer
        10
    });

    // 3. PDF (Portable Document Format)
    // Header: 25 50 44 46 (%PDF)
    // Footer: 25 25 45 4F 46 (%%EOF)
    signatures_.push_back({
        "PDF",
        "pdf",
        "application/pdf",
        {0x25, 0x50, 0x44, 0x46}, // %PDF
        {},
        {0x25, 0x25, 0x45, 0x4F, 0x46}, // %%EOF
        128,                         // Min 128 bytes
        500ULL * 1024ULL * 1024ULL,  // Max 500 MB
        CarvingStrategy::HeaderFooter,
        10
    });

    // 4. ZIP Archive (and container for DOCX, XLSX, PPTX, APK, JAR)
    // Header: 50 4B 03 04 (PK\x03\x04)
    // End of Central Directory Record: 50 4B 05 06 (PK\x05\x06) + 18-byte minimum comment trailer
    signatures_.push_back({
        "ZIP",
        "zip",
        "application/zip",
        {0x50, 0x4B, 0x03, 0x04},
        {},
        {0x50, 0x4B, 0x05, 0x06},
        22,                          // Min 22 bytes (empty zip)
        500ULL * 1024ULL * 1024ULL,  // Max 500 MB
        CarvingStrategy::EmbeddedStructures,
        5 // Generic ZIP priority is 5; specific Office types will be higher or classified
    });

    // 5. MP3 Audio (MPEG-1/2 Audio Layer III)
    // Option A: ID3v2 container -> Header: 49 44 33 ("ID3")
    signatures_.push_back({
        "MP3",
        "mp3",
        "audio/mpeg",
        {0x49, 0x44, 0x33}, // "ID3" tag
        {},
        {},
        256,
        100ULL * 1024ULL * 1024ULL,
        CarvingStrategy::FrameBased,
        10
    });

    // Option B: Raw MPEG audio sync frame -> FF FB or FF F3 or FF F2
    signatures_.push_back({
        "MP3",
        "mp3",
        "audio/mpeg",
        {0xFF, 0xFB},
        {0xFF, 0xFE}, // Mask: first 11 bits set (frame sync 0xFFE0)
        {},
        512,
        100ULL * 1024ULL * 1024ULL,
        CarvingStrategy::FrameBased,
        4
    });

    // 6. MP4 Video (MPEG-4 Part 14 / QuickTime container)
    // Header: 4 bytes size followed by 'ftyp' (66 74 79 70)
    // So bytes [4..7] == 'ftyp'
    // We can define 8-byte header with mask: 00 00 00 00 66 74 79 70
    signatures_.push_back({
        "MP4",
        "mp4",
        "video/mp4",
        {0x00, 0x00, 0x00, 0x00, 0x66, 0x74, 0x79, 0x70}, // ????ftyp
        {0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF},
        {},
        512,
        1024ULL * 1024ULL * 1024ULL, // Max 1 GB
        CarvingStrategy::LengthInHeader,
        10
    });

    // Sort by priority
    std::sort(signatures_.begin(), signatures_.end(), [](const FileSignature& a, const FileSignature& b) {
        return a.priority > b.priority;
    });
}

std::vector<const FileSignature*> SignatureDatabase::matchHeader(const uint8_t* data, size_t length) const {
    std::vector<const FileSignature*> matches;
    for (const auto& sig : signatures_) {
        if (length < sig.header.size()) continue;

        if (sig.headerMask.empty()) {
            if (core::BinaryUtils::matchesSignature(data, length, sig.header.data(), sig.header.size())) {
                matches.push_back(&sig);
            }
        } else {
            if (core::BinaryUtils::matchesMaskedSignature(data, length, 
                                                         sig.header.data(), 
                                                         sig.headerMask.data(), 
                                                         sig.header.size())) {
                matches.push_back(&sig);
            }
        }
    }
    return matches;
}

} // namespace forensivault::carving
