#include "test_framework.hpp"
#include "sanitization/drive_types.hpp"
#include "sanitization/drive_detector.hpp"
#include "sanitization/sanitization_strategy.hpp"
#include "sanitization/sanitization_verifier.hpp"
#include "sanitization/hdd_sanitizer.hpp"
#include "sanitization/ssd_sanitizer.hpp"
#include "sanitization/image_sanitizer.hpp"
#include "logging/audit_logger.hpp"
#include "forensivault/common/crypto_hash.hpp"
#include <fstream>
#include <filesystem>
#include <vector>

namespace fs = std::filesystem;
using namespace forensivault;
using namespace forensivault::sanitization;
using namespace forensivault::logging;

namespace {

void createTestDriveImage(const std::string& path, size_t sizeBytes, uint8_t pattern = 0x5A) {
    fs::create_directories(fs::path(path).parent_path());
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    std::vector<uint8_t> data(sizeBytes, pattern);
    ofs.write(reinterpret_cast<const char*>(data.data()), data.size());
}

} // anonymous namespace

FV_TEST(DriveSanitization, DetectorProbesVirtualImageProperties) {
    std::string imgPath = "test_data/sample_disk.img";
    createTestDriveImage(imgPath, 1024 * 1024, 0x5A);
    auto props = DriveDetector::detectImage(imgPath, DriveMediaType::DISK_IMAGE_RAW);

    ASSERT_TRUE(props.is_safe_to_sanitize);
    ASSERT_FALSE(props.is_physical_device);
    ASSERT_EQ(props.sector_size, 512U);
    ASSERT_TRUE(props.total_bytes > 0);
    ASSERT_EQ(props.media_type, DriveMediaType::DISK_IMAGE_RAW);
    ASSERT_EQ(props.interface_type, DriveInterface::VIRTUAL_IMAGE);
    ASSERT_TRUE(props.capabilities.size() > 0);
}

FV_TEST(DriveSanitization, PhysicalDevicesDetectedAsSanitizeProhibited) {
    auto physicalDevs = DriveDetector::detectPhysicalDevices();
    ASSERT_TRUE(physicalDevs.size() > 0);

    for (const auto& dev : physicalDevs) {
        ASSERT_TRUE(dev.is_physical_device);
        ASSERT_FALSE(dev.is_safe_to_sanitize); // Strictly prohibited in prototype
        ASSERT_TRUE(dev.hardware_limitations.size() > 0);
    }
}

FV_TEST(DriveSanitization, StrategySeparationAndBufferGeneration) {
    // 1. NIST Clear Strategy
    NistClearStrategy nist;
    ASSERT_EQ(nist.totalPasses(), 1);
    std::vector<uint8_t> nistBuf(1024, 0xFF);
    nist.fillPassBuffer(1, nistBuf.data(), nistBuf.size());
    for (uint8_t b : nistBuf) {
        ASSERT_EQ(b, 0x00);
    }

    // 2. DoD 5220.22-M Strategy (Pass 1 = 0x00, Pass 2 = 0xFF, Pass 3 = Random)
    Dod522022MStrategy dod;
    ASSERT_EQ(dod.totalPasses(), 3);
    std::vector<uint8_t> dodBuf(1024, 0xAA);
    dod.fillPassBuffer(1, dodBuf.data(), dodBuf.size());
    ASSERT_EQ(dodBuf[0], 0x00);

    dod.fillPassBuffer(2, dodBuf.data(), dodBuf.size());
    ASSERT_EQ(dodBuf[0], 0xFF);

    dod.fillPassBuffer(3, dodBuf.data(), dodBuf.size());
    double randEntropy = CryptoHash::calculateEntropy(dodBuf);
    ASSERT_TRUE(randEntropy > 7.0);

    // 3. Firmware Erase Strategy
    AtaNvmeFirmwareEraseStrategy fw;
    ASSERT_EQ(fw.totalPasses(), 0);
    ASSERT_TRUE(fw.isHardwareFirmwareCommand());
}

FV_TEST(DriveSanitization, SsdSanitizerDisclosesNandLimitations) {
    DriveProperties ssdProps;
    ssdProps.device_identifier = "NVMe-SSD-01";
    ssdProps.media_type = DriveMediaType::SSD_NAND;
    ssdProps.interface_type = DriveInterface::NVME;
    ssdProps.supports_sanitize_crypto = true;
    ssdProps.supports_trim = true;

    auto eval = SSDSanitizer::evaluateCapabilities(ssdProps);
    ASSERT_FALSE(eval.software_overwrite_sufficient); // Logical overwrite is never sufficient
    ASSERT_TRUE(eval.supports_nvme_crypto_erase);
    ASSERT_TRUE(eval.supports_trim_deallocate);
    ASSERT_TRUE(eval.critical_disclosures.size() > 0);
    ASSERT_TRUE(eval.unverifiable_aspects.size() > 0);
}

FV_TEST(DriveSanitization, ExplicitConfirmationEnforcedBeforeImageSanitization) {
    std::string testPath = "test_data/disposable/test_unconfirmed.img";
    createTestDriveImage(testPath, 32768, 0x77);

    std::string shaBefore = ImageSanitizer::computeImageSha256(testPath);
    ASSERT_FALSE(shaBefore.empty());

    ImageSanitizer sanitizer;
    NistClearStrategy strategy;

    // Without confirmation
    auto rep = sanitizer.sanitizeImage(testPath, strategy, false);
    ASSERT_FALSE(rep.verified);
    ASSERT_TRUE(rep.summary.find("ABORTED") != std::string::npos);

    // Verify image on disk was completely untouched
    std::string shaAfter = ImageSanitizer::computeImageSha256(testPath);
    ASSERT_EQ(shaBefore, shaAfter);

    fs::remove(testPath);
}

FV_TEST(DriveSanitization, EndToEndNistClearImageSanitizationAndVerification) {
    std::string testPath = "test_data/disposable/test_drive_nist.img";
    const size_t imageBytes = 64 * 1024; // 64 KB
    createTestDriveImage(testPath, imageBytes, 0x33);

    std::string shaBefore = ImageSanitizer::computeImageSha256(testPath);

    ImageSanitizer sanitizer;
    NistClearStrategy strategy;
    bool progressTriggered = false;

    auto cb = [&](const EraseProgress& p) {
        progressTriggered = true;
        ASSERT_TRUE(p.percentage >= 0.0);
    };

    auto rep = sanitizer.sanitizeImage(testPath, strategy, true, cb);

    ASSERT_TRUE(progressTriggered);
    ASSERT_TRUE(rep.verified);
    ASSERT_EQ(rep.passes_completed, 1);
    ASSERT_EQ(rep.total_bytes_sanitized, static_cast<uint64_t>(imageBytes));
    ASSERT_EQ(rep.match_rate_percentage, 100.0);
    ASSERT_EQ(rep.measured_entropy, 0.0); // Completely zeroed
    ASSERT_NE(rep.pre_wipe_sha256, rep.post_wipe_sha256);
    ASSERT_FALSE(rep.start_timestamp_iso.empty());
    ASSERT_FALSE(rep.end_timestamp_iso.empty());
    ASSERT_TRUE(rep.audit_entry_id > 0);

    // Verify audit chain integrity
    ASSERT_TRUE(AuditLogger::getInstance().verifyChain());

    // Verify raw file content is 100% 0x00
    std::ifstream checkStream(testPath, std::ios::binary);
    std::vector<uint8_t> postData(imageBytes);
    checkStream.read(reinterpret_cast<char*>(postData.data()), imageBytes);
    checkStream.close();
    for (uint8_t b : postData) {
        ASSERT_EQ(b, 0x00);
    }

    fs::remove(testPath);
}

FV_TEST(DriveSanitization, EndToEndDod3PassImageSanitization) {
    std::string testPath = "test_data/disposable/test_drive_dod.img";
    const size_t imageBytes = 32 * 1024; // 32 KB
    createTestDriveImage(testPath, imageBytes, 0x44);

    ImageSanitizer sanitizer;
    Dod522022MStrategy dod;

    auto rep = sanitizer.sanitizeImage(testPath, dod, true);

    ASSERT_TRUE(rep.verified);
    ASSERT_EQ(rep.passes_completed, 3);
    ASSERT_NE(rep.pre_wipe_sha256, rep.post_wipe_sha256);
    ASSERT_TRUE(rep.measured_entropy > 7.0); // High entropy due to Pass 3 random bytes

    fs::remove(testPath);
}
