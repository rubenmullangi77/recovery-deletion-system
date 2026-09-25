#include "test_framework.hpp"
#include "forensivault/common/crypto_hash.hpp"
#include <string>
#include <vector>

using namespace forensivault;

FV_TEST(CryptoHash, Sha256StandardVectors) {
    // NIST standard test vectors
    // 1. Empty string
    ASSERT_EQ(CryptoHash::sha256(""), 
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    // 2. "abc"
    ASSERT_EQ(CryptoHash::sha256("abc"), 
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    // 3. "The quick brown fox jumps over the lazy dog"
    ASSERT_EQ(CryptoHash::sha256("The quick brown fox jumps over the lazy dog"), 
              "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");
}

FV_TEST(CryptoHash, Sha256StreamingEquivalence) {
    std::string part1 = "Forensic ";
    std::string part2 = "Evidence ";
    std::string part3 = "Integrity 2026";
    std::string full = part1 + part2 + part3;

    CryptoHash::Sha256Context ctx;
    ctx.update(reinterpret_cast<const uint8_t*>(part1.data()), part1.size());
    ctx.update(reinterpret_cast<const uint8_t*>(part2.data()), part2.size());
    ctx.update(reinterpret_cast<const uint8_t*>(part3.data()), part3.size());
    std::string streamHash = ctx.finalize();

    std::string directHash = CryptoHash::sha256(full);
    ASSERT_EQ(streamHash, directHash);
}

FV_TEST(CryptoHash, Md5StandardVectors) {
    // RFC 1321 standard test vectors
    // 1. Empty string
    ASSERT_EQ(CryptoHash::md5(""), 
              "d41d8cd98f00b204e9800998ecf8427e");

    // 2. "abc"
    ASSERT_EQ(CryptoHash::md5("abc"), 
              "900150983cd24fb0d6963f7d28e17f72");

    // 3. "The quick brown fox jumps over the lazy dog"
    ASSERT_EQ(CryptoHash::md5("The quick brown fox jumps over the lazy dog"), 
              "9e107d9d372bb6826bd81d3542a419d6");
}

FV_TEST(CryptoHash, Crc32StandardVectors) {
    // Standard IEEE 802.3 check value for "123456789" is 0xCBF43926
    std::string testStr = "123456789";
    uint32_t crc = CryptoHash::crc32(reinterpret_cast<const uint8_t*>(testStr.data()), testStr.size());
    ASSERT_EQ(crc, 0xcbf43926);
}

FV_TEST(CryptoHash, ShannonEntropyCalculations) {
    // Uniform zero buffer (e.g. wiped sector) must have exactly 0.0 entropy
    ByteBuffer zeroSector(512, 0x00);
    double zeroEntropy = CryptoHash::calculateEntropy(zeroSector);
    ASSERT_NEAR(zeroEntropy, 0.0, 0.0001);

    // Uniform 0xFF buffer must also have 0.0 entropy
    ByteBuffer onesSector(512, 0xFF);
    double onesEntropy = CryptoHash::calculateEntropy(onesSector);
    ASSERT_NEAR(onesEntropy, 0.0, 0.0001);

    // Perfectly balanced 256-byte distribution (one of each byte) must have exactly 8.0 bits/byte
    ByteBuffer maxEntropyBuffer(256);
    for (size_t i = 0; i < 256; ++i) {
        maxEntropyBuffer[i] = static_cast<uint8_t>(i);
    }
    double maxEntropy = CryptoHash::calculateEntropy(maxEntropyBuffer);
    ASSERT_NEAR(maxEntropy, 8.0, 0.0001);
}
