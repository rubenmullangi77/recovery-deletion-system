#include "test_framework.hpp"
#include "carving/file_signature.hpp"
#include "carving/format_validator.hpp"
#include "carving/signature_scanner.hpp"
#include "carving/file_carver.hpp"
#include "core/disk_image_reader.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>

using namespace forensivault::carving;
using namespace forensivault::core;
namespace fs = std::filesystem;

FV_TEST(CarvingEngine, SignatureDatabaseDefaults) {
    SignatureDatabase db;
    const auto& sigs = db.getSignatures();
    ASSERT_TRUE(sigs.size() >= 6);

    // Verify JPEG, PNG, PDF, ZIP, MP3, MP4 exist
    bool hasJpeg = false, hasPng = false, hasPdf = false, hasZip = false, hasMp3 = false, hasMp4 = false;
    for (const auto& s : sigs) {
        if (s.fileType == "JPEG") hasJpeg = true;
        if (s.fileType == "PNG") hasPng = true;
        if (s.fileType == "PDF") hasPdf = true;
        if (s.fileType == "ZIP") hasZip = true;
        if (s.fileType == "MP3") hasMp3 = true;
        if (s.fileType == "MP4") hasMp4 = true;
    }
    ASSERT_TRUE(hasJpeg);
    ASSERT_TRUE(hasPng);
    ASSERT_TRUE(hasPdf);
    ASSERT_TRUE(hasZip);
    ASSERT_TRUE(hasMp3);
    ASSERT_TRUE(hasMp4);
}

FV_TEST(CarvingEngine, FormatValidatorRejectsFalsePositives) {
    FileSignature fakeJpeg{
        "JPEG", "jpg", "image/jpeg",
        {0xFF, 0xD8, 0xFF}, {}, {0xFF, 0xD9},
        64, 1024 * 1024, CarvingStrategy::HeaderFooter, 10
    };

    // Header found, but body is truncated and lacks EOI (0xFF 0xD9)
    std::vector<uint8_t> corruptedJpeg(128, 0x00);
    corruptedJpeg[0] = 0xFF; corruptedJpeg[1] = 0xD8; corruptedJpeg[2] = 0xFF; corruptedJpeg[3] = 0xE0;

    auto res = FormatValidator::validate(fakeJpeg, corruptedJpeg.data(), corruptedJpeg.size());
    ASSERT_FALSE(res.isValid);
    ASSERT_TRUE(res.confidenceScore < 50.0);
}

FV_TEST(CarvingEngine, FormatValidatorPngValidation) {
    FileSignature pngSig{
        "PNG", "png", "image/png",
        {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, {},
        {0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82},
        45, 1024 * 1024, CarvingStrategy::LengthInHeader, 10
    };

    // Construct valid minimal PNG byte slice
    // Header (8) + IHDR (12 + 13 = 25) + IEND (12)
    std::vector<uint8_t> validPng = {
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
        0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR len 13
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4, 0x89, // CRC
        0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, // IEND len 0
        0xAE, 0x42, 0x60, 0x82                          // CRC
    };

    auto res = FormatValidator::validate(pngSig, validPng.data(), validPng.size());
    ASSERT_TRUE(res.isValid);
    ASSERT_EQ(res.trueLength, validPng.size());
    ASSERT_TRUE(res.confidenceScore >= 95.0);
}

FV_TEST(CarvingEngine, EndToEndCarvingOnSyntheticImage) {
    std::string testImage = "test_data/carving_evidence.img";
    if (!fs::exists(testImage)) {
        return;
    }
    DiskImageReader reader(testImage);
    ASSERT_TRUE(reader.isOpen());

    // Clean up past recovery folder if present
    std::string recoveryDir = "test_data/test_recovered";
    fs::remove_all(recoveryDir);

    CarverOptions options;
    options.outputDirectory = recoveryDir;
    options.organizeByType = true;
    options.validateIntegrity = true;
    options.minimumConfidence = 25.0;

    FileCarver carver(options);
    CarvingSessionResult result = carver.carve(reader);

    ASSERT_TRUE(result.signaturesDiscovered >= 7);
    ASSERT_TRUE(result.filesSuccessfullyCarved >= 6);
    ASSERT_TRUE(result.validFilesCount >= 5);

    // Verify individual files carved and validated
    bool foundJpeg = false, foundPng = false, foundPdf = false, foundDocx = false, foundZip = false;
    for (const auto& file : result.carvedFiles) {
        if (file.fileType == "JPEG" && file.isValid) foundJpeg = true;
        if (file.fileType == "PNG" && file.isValid) foundPng = true;
        if (file.fileType == "PDF" && file.isValid) foundPdf = true;
        if (file.fileType == "DOCX" && file.isValid) foundDocx = true;
        if (file.fileType == "ZIP" && file.isValid) foundZip = true;

        // Verify extracted file exists on disk
        if (!file.recoveredFilePath.empty()) {
            ASSERT_TRUE(fs::exists(file.recoveredFilePath));
            ASSERT_EQ(fs::file_size(file.recoveredFilePath), file.lengthBytes);
        }
    }

    ASSERT_TRUE(foundJpeg);
    ASSERT_TRUE(foundPng);
    ASSERT_TRUE(foundPdf);
    ASSERT_TRUE(foundDocx);
    ASSERT_TRUE(foundZip);

    // Verify subdirectories created (e.g. test_recovered/JPG/, test_recovered/PNG/, test_recovered/PDF/, test_recovered/DOCX/)
    ASSERT_TRUE(fs::exists(recoveryDir + "/JPG"));
    ASSERT_TRUE(fs::exists(recoveryDir + "/PNG"));
    ASSERT_TRUE(fs::exists(recoveryDir + "/PDF"));
    ASSERT_TRUE(fs::exists(recoveryDir + "/DOCX"));
    ASSERT_TRUE(fs::exists(recoveryDir + "/ZIP"));

    // Cleanup
    fs::remove_all(recoveryDir);
}
