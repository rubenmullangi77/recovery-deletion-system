#include "test_framework.hpp"
#include "core/binary_utils.hpp"
#include "forensivault/common/crypto_hash.hpp"
#include <vector>
#include <string>

using namespace forensivault::core;

FV_TEST(BinaryUtils, HexadecimalConversion) {
    ASSERT_EQ(BinaryUtils::byteToHex(0x00), "00");
    ASSERT_EQ(BinaryUtils::byteToHex(0xFF), "FF");
    ASSERT_EQ(BinaryUtils::byteToHex(0x0A), "0A");
    ASSERT_EQ(BinaryUtils::byteToHex(0xA5), "A5");
    ASSERT_EQ(BinaryUtils::byteToHex(0xA5, false), "a5");

    std::vector<uint8_t> bytes = {0xFF, 0xD8, 0xFF, 0xE0};
    ASSERT_EQ(BinaryUtils::toHex(bytes), "FF D8 FF E0");
    ASSERT_EQ(BinaryUtils::toHex(bytes, ":"), "FF:D8:FF:E0");
    ASSERT_EQ(BinaryUtils::toHex(bytes, ""), "FFD8FFE0");

    // fromHex parsing
    std::vector<uint8_t> parsed = BinaryUtils::fromHex("FF D8 FF E0");
    ASSERT_EQ(parsed.size(), 4ULL);
    ASSERT_EQ(parsed[0], 0xFF);
    ASSERT_EQ(parsed[1], 0xD8);
    ASSERT_EQ(parsed[2], 0xFF);
    ASSERT_EQ(parsed[3], 0xE0);

    std::vector<uint8_t> parsedContinuous = BinaryUtils::fromHex("55aa");
    ASSERT_EQ(parsedContinuous.size(), 2ULL);
    ASSERT_EQ(parsedContinuous[0], 0x55);
    ASSERT_EQ(parsedContinuous[1], 0xAA);
}

FV_TEST(BinaryUtils, BinaryConversion) {
    ASSERT_EQ(BinaryUtils::byteToBinary(0x00), "00000000");
    ASSERT_EQ(BinaryUtils::byteToBinary(0xFF), "11111111");
    ASSERT_EQ(BinaryUtils::byteToBinary(0xAA), "10101010");
    ASSERT_EQ(BinaryUtils::byteToBinary(0x55), "01010101");
    ASSERT_EQ(BinaryUtils::byteToBinary(0x81), "10000001");

    std::vector<uint8_t> bytes = {0xAA, 0x55};
    ASSERT_EQ(BinaryUtils::toBinary(bytes), "10101010 01010101");
}

FV_TEST(BinaryUtils, ByteSearching) {
    std::string text = "EVIDENCE_BLOCK_START_FORENSIC_TARGET_EVIDENCE_BLOCK_END";
    std::vector<uint8_t> haystack(text.begin(), text.end());

    std::string needleText = "FORENSIC";
    std::vector<uint8_t> needle(needleText.begin(), needleText.end());

    int64_t foundIdx = BinaryUtils::findFirst(haystack, needle);
    ASSERT_EQ(foundIdx, 21LL);

    // Non-existent pattern
    std::string missingText = "NOT_HERE";
    std::vector<uint8_t> missingNeedle(missingText.begin(), missingText.end());
    ASSERT_EQ(BinaryUtils::findFirst(haystack, missingNeedle), -1LL);

    // Multiple occurrences
    std::string occText = "EVIDENCE";
    std::vector<uint8_t> occNeedle(occText.begin(), occText.end());
    auto allMatches = BinaryUtils::findAll(haystack, occNeedle);
    ASSERT_EQ(allMatches.size(), 2ULL);
    ASSERT_EQ(allMatches[0], 0ULL);
    ASSERT_EQ(allMatches[1], 37ULL);

    // Binary byte search with Boyer-Moore-Horspool
    std::vector<uint8_t> rawStream = {
        0x00, 0x11, 0x22, 0xFF, 0xD8, 0xFF, 0xE0, 0xAA, 0xBB, 0xFF, 0xD8, 0xFF, 0xE1
    };
    std::vector<uint8_t> jpegMagic = {0xFF, 0xD8, 0xFF};
    auto jpegMatches = BinaryUtils::findAll(rawStream, jpegMagic);
    ASSERT_EQ(jpegMatches.size(), 2ULL);
    ASSERT_EQ(jpegMatches[0], 3ULL);
    ASSERT_EQ(jpegMatches[1], 9ULL);
}

FV_TEST(BinaryUtils, ByteSignatureComparison) {
    std::vector<uint8_t> data = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}; // PNG signature
    std::vector<uint8_t> pngSig = {0x89, 0x50, 0x4E, 0x47};
    std::vector<uint8_t> pdfSig = {0x25, 0x50, 0x44, 0x46};

    ASSERT_TRUE(BinaryUtils::matchesSignature(data, pngSig));
    ASSERT_FALSE(BinaryUtils::matchesSignature(data, pdfSig));

    // Masked comparison (wildcards)
    // Match 0x89 ?? 0x4E 0x47
    uint8_t expectedSig[] = {0x89, 0x00, 0x4E, 0x47};
    uint8_t mask[]        = {0xFF, 0x00, 0xFF, 0xFF};
    ASSERT_TRUE(BinaryUtils::matchesMaskedSignature(data.data(), data.size(), expectedSig, mask, 4));
}

FV_TEST(BinaryUtils, OffsetCalculations) {
    // Sector 0
    ASSERT_EQ(BinaryUtils::sectorToByteOffset(0, 512), 0ULL);
    ASSERT_EQ(BinaryUtils::byteToSector(0, 512), 0ULL);
    ASSERT_EQ(BinaryUtils::offsetWithinSector(0, 512), 0U);
    ASSERT_EQ(BinaryUtils::alignToSector(0, 512), 0ULL);

    // Sector 3 (offset 1536)
    ASSERT_EQ(BinaryUtils::sectorToByteOffset(3, 512), 1536ULL);
    ASSERT_EQ(BinaryUtils::byteToSector(1536, 512), 3ULL);
    ASSERT_EQ(BinaryUtils::offsetWithinSector(1536, 512), 0U);

    // Offset 1550 (Sector 3 + 14 bytes)
    ASSERT_EQ(BinaryUtils::byteToSector(1550, 512), 3ULL);
    ASSERT_EQ(BinaryUtils::offsetWithinSector(1550, 512), 14U);
    ASSERT_EQ(BinaryUtils::alignToSector(1550, 512), 1536ULL);

    // Sector span calculations
    // Byte 500 to 520 (length 20) spans byte 500 in sector 0 to byte 519 in sector 1 (2 sectors)
    ASSERT_EQ(BinaryUtils::calculateSectorSpan(500, 20, 512), 2ULL);

    // Byte 512 with length 512 (bytes 512..1023) is exactly 1 sector (sector 1)
    ASSERT_EQ(BinaryUtils::calculateSectorSpan(512, 512, 512), 1ULL);

    // Byte 512 with length 1024 (bytes 512..1535) is exactly 2 sectors (sectors 1 and 2)
    ASSERT_EQ(BinaryUtils::calculateSectorSpan(512, 1024, 512), 2ULL);
}

FV_TEST(BinaryUtils, Sha256Hashing) {
    std::string text = "Forensic Binary Analysis Layer Test 2026";
    std::vector<uint8_t> data(text.begin(), text.end());

    std::string hash = BinaryUtils::sha256(data);
    ASSERT_EQ(hash.length(), 64ULL);

    // Check consistency
    std::string direct = forensivault::CryptoHash::sha256(text);
    ASSERT_EQ(hash, direct);
}
