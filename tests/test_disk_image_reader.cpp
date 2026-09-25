#include "test_framework.hpp"
#include "core/disk_image_reader.hpp"
#include "forensivault/common/crypto_hash.hpp"
#include <fstream>
#include <vector>
#include <string>
#include <cstring>

using namespace forensivault;
using namespace forensivault::core;

namespace {

// Helper to create a reproducible test image file
std::string createTestDiskImage(const std::string& path, size_t numSectors = 16, size_t sectorSize = 512) {
    size_t totalBytes = numSectors * sectorSize;
    std::vector<uint8_t> data(totalBytes, 0);

    // Sector 0: MBR signature simulation
    data[0] = 0xEB; data[1] = 0x3C; data[2] = 0x90;
    const std::string mbrMsg = "FORENSIVAULT_TEST_BOOT";
    std::memcpy(data.data() + 3, mbrMsg.data(), mbrMsg.size());
    data[510] = 0x55;
    data[511] = 0xAA;

    // Sector 1: Pattern fill 0xCC
    std::memset(data.data() + sectorSize, 0xCC, sectorSize);

    // Sector 2: Arbitrary payload
    const std::string payload = "CONFIDENTIAL_EVIDENCE_PAYLOAD_SECTOR_2";
    std::memcpy(data.data() + (2 * sectorSize) + 50, payload.data(), payload.size());

    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(data.data()), data.size());
    out.close();

    return path;
}

} // anonymous namespace

FV_TEST(DiskImageReader, OpenAndVerifyGeometry) {
    std::string testPath = "test_data/test_open.img";
    createTestDiskImage(testPath, 16, 512);

    DiskImageReader reader(testPath);
    ASSERT_TRUE(reader.isOpen());
    ASSERT_EQ(reader.size(), 16ULL * 512ULL);
    ASSERT_EQ(reader.sectorSize(), 512U);
    ASSERT_EQ(reader.totalSectors(), 16ULL);
    ASSERT_EQ(reader.filepath(), testPath);
}

FV_TEST(DiskImageReader, ReadArbitraryByteRanges) {
    std::string testPath = "test_data/test_ranges.img";
    createTestDiskImage(testPath, 16, 512);

    DiskImageReader reader(testPath);
    ASSERT_TRUE(reader.isOpen());

    // Read MBR marker string from offset 3
    uint8_t buffer[23] = {0};
    bool ok = reader.read(3, buffer, 22);
    ASSERT_TRUE(ok);
    std::string readStr(reinterpret_cast<char*>(buffer), 22);
    ASSERT_EQ(readStr, "FORENSIVAULT_TEST_BOOT");

    // Read payload from Sector 2 (offset = 2 * 512 + 50 = 1074)
    std::vector<uint8_t> payloadBytes = reader.readBytes(1074, 38);
    ASSERT_EQ(payloadBytes.size(), 38ULL);
    std::string payloadStr(reinterpret_cast<char*>(payloadBytes.data()), 38);
    ASSERT_EQ(payloadStr, "CONFIDENTIAL_EVIDENCE_PAYLOAD_SECTOR_2");
}

FV_TEST(DiskImageReader, ReadSectors) {
    std::string testPath = "test_data/test_sectors.img";
    createTestDiskImage(testPath, 16, 512);

    DiskImageReader reader(testPath);
    ASSERT_TRUE(reader.isOpen());

    // Read Sector 0
    auto sector0 = reader.readSector(0);
    ASSERT_EQ(sector0.size(), 512ULL);
    ASSERT_EQ(sector0[510], 0x55);
    ASSERT_EQ(sector0[511], 0xAA);

    // Read Sector 1 into raw buffer
    uint8_t sector1[512];
    ASSERT_TRUE(reader.readSector(1, sector1));
    for (size_t i = 0; i < 512; ++i) {
        ASSERT_EQ(sector1[i], 0xCC);
    }
}

FV_TEST(DiskImageReader, SeekAndTell) {
    std::string testPath = "test_data/test_seek.img";
    createTestDiskImage(testPath, 16, 512);

    DiskImageReader reader(testPath);
    ASSERT_TRUE(reader.isOpen());

    ASSERT_TRUE(reader.seek(510));
    ASSERT_EQ(reader.tell(), 510ULL);

    uint8_t sig[2] = {0};
    ASSERT_TRUE(reader.read(510, sig, 2));
    ASSERT_EQ(sig[0], 0x55);
    ASSERT_EQ(sig[1], 0xAA);
}

FV_TEST(DiskImageReader, ErrorDetectionAndBoundsSafety) {
    std::string testPath = "test_data/test_bounds.img";
    createTestDiskImage(testPath, 16, 512); // Total 8192 bytes

    DiskImageReader reader(testPath);
    ASSERT_TRUE(reader.isOpen());

    // Read past EOF
    uint8_t buf[100];
    ASSERT_FALSE(reader.read(8150, buf, 100));
    ASSERT_NE(reader.lastError(), "");

    // Seek past EOF
    ASSERT_FALSE(reader.seek(9000));
    ASSERT_NE(reader.lastError(), "");

    // Read invalid sector
    auto badSector = reader.readSector(99);
    ASSERT_TRUE(badSector.empty());

    // Non-existent image file
    DiskImageReader nonExistent("test_data/non_existent_image.dd");
    ASSERT_FALSE(nonExistent.isOpen());
    ASSERT_NE(nonExistent.lastError(), "");
}

FV_TEST(DiskImageReader, EvidenceImmutabilityGuarantee) {
    std::string testPath = "test_data/test_immutability.img";
    createTestDiskImage(testPath, 16, 512);

    // Compute SHA-256 before any operations
    std::ifstream beforeStream(testPath, std::ios::binary);
    std::vector<uint8_t> beforeData((std::istreambuf_iterator<char>(beforeStream)),
                                     std::istreambuf_iterator<char>());
    beforeStream.close();
    std::string hashBefore = CryptoHash::sha256(beforeData);

    // Perform intensive read, seek, boundary checks
    {
        DiskImageReader reader(testPath);
        ASSERT_TRUE(reader.isOpen());

        for (uint64_t s = 0; s < 16; ++s) {
            auto sec = reader.readSector(s);
            ASSERT_EQ(sec.size(), 512ULL);
        }

        uint8_t temp[256];
        reader.read(0, temp, sizeof(temp));
        reader.seek(100);
        reader.read(8000, temp, 50);

        // Attempt intentional out of bounds reads
        reader.read(8190, temp, 20);
        reader.seek(99999);
    } // reader closes here

    // Verify hash after all operations
    std::ifstream afterStream(testPath, std::ios::binary);
    std::vector<uint8_t> afterData((std::istreambuf_iterator<char>(afterStream)),
                                    std::istreambuf_iterator<char>());
    afterStream.close();
    std::string hashAfter = CryptoHash::sha256(afterData);

    ASSERT_EQ(hashBefore, hashAfter);
}
