#include "test_framework.hpp"
#include "carving/fragment_reconstructor.hpp"
#include "carving/format_validator.hpp"
#include "core/disk_image_reader.hpp"
#include "core/binary_utils.hpp"
#include "forensivault/common/crypto_hash.hpp"
#include <vector>
#include <string>
#include <iostream>
#include <filesystem>

namespace fs = std::filesystem;

using namespace forensivault;
using namespace forensivault::carving;
using namespace forensivault::core;

FV_TEST(FragmentAnalysis, ModelCompatibilityEvaluation) {
    FragmentCandidate headerFrag;
    headerFrag.fragmentId = 1;
    headerFrag.offset = 1024;
    headerFrag.length = 512;
    headerFrag.fileType = "JPEG";
    headerFrag.role = FragmentRole::Header;
    headerFrag.entropy = 6.2;

    FragmentCandidate footerFrag;
    footerFrag.fragmentId = 2;
    footerFrag.offset = 2048;
    footerFrag.length = 512;
    footerFrag.fileType = "JPEG";
    footerFrag.role = FragmentRole::Footer;
    footerFrag.entropy = 6.0;

    FragmentCandidate mismatchedFrag;
    mismatchedFrag.fragmentId = 3;
    mismatchedFrag.offset = 3072;
    mismatchedFrag.length = 512;
    mismatchedFrag.fileType = "PNG";
    mismatchedFrag.role = FragmentRole::Footer;
    mismatchedFrag.entropy = 6.1;

    FragmentCandidate backwardsFrag;
    backwardsFrag.fragmentId = 4;
    backwardsFrag.offset = 512; // Behind header
    backwardsFrag.length = 512;
    backwardsFrag.fileType = "JPEG";
    backwardsFrag.role = FragmentRole::Footer;
    backwardsFrag.entropy = 6.0;

    // Header and Footer of same type in forward direction are compatible
    ASSERT_TRUE(FragmentReconstructor::evaluateCompatibility(headerFrag, footerFrag));

    // Mismatched file types must be rejected
    ASSERT_FALSE(FragmentReconstructor::evaluateCompatibility(headerFrag, mismatchedFrag));

    // Backwards fragments (offset before header) must be rejected
    ASSERT_FALSE(FragmentReconstructor::evaluateCompatibility(headerFrag, backwardsFrag));
}

FV_TEST(FragmentAnalysis, ReconstructDisjointJpegFragments) {
    std::string imgPath = "test_data/fragmented_evidence.img";
    if (!fs::exists(imgPath)) {
        return;
    }
    DiskImageReader reader(imgPath);
    ASSERT_TRUE(reader.isOpen());

    // Read full image buffer
    std::vector<uint8_t> imgBuffer = reader.readBytes(0, static_cast<size_t>(reader.size()));
    ASSERT_EQ(imgBuffer.size(), 32768ULL);

    // Read Fragment 1 (Sector 2: offset 1024, len 110)
    std::vector<uint8_t> frag1Bytes = reader.readBytes(1024, 110);
    FragmentCandidate headerFrag;
    headerFrag.fragmentId = 1;
    headerFrag.offset = 1024;
    headerFrag.length = 110;
    headerFrag.startSector = 2;
    headerFrag.fileType = "JPEG";
    headerFrag.role = FragmentRole::Header;
    headerFrag.entropy = CryptoHash::calculateEntropy(frag1Bytes);
    headerFrag.data = frag1Bytes;
    headerFrag.confidence = 50.0;

    // Discover orphan candidates in unallocated space after sector 2
    auto orphans = FragmentReconstructor::findOrphanFragments(
        "JPEG", imgBuffer.data() + 1536, 1536, imgBuffer.size() - 1536, 512);

    ASSERT_FALSE(orphans.empty());

    // Verify orphan footer located at Sector 5 (offset 2560)
    bool foundFooterOrphan = false;
    for (const auto& o : orphans) {
        if (o.offset == 2560 && o.role == FragmentRole::Footer) {
            foundFooterOrphan = true;
        }
    }
    ASSERT_TRUE(foundFooterOrphan);

    // Attempt conservative reconstruction
    auto result = FragmentReconstructor::attemptReconstruction(headerFrag, orphans, 1024 * 1024);

    ASSERT_TRUE(result.isReconstructed);
    ASSERT_FALSE(result.isPartial);
    ASSERT_EQ(result.fileType, "JPEG");
    ASSERT_EQ(result.fragmentOffsets.size(), 2ULL);
    ASSERT_EQ(result.fragmentOffsets[0], 1024ULL);
    ASSERT_EQ(result.fragmentOffsets[1], 2560ULL);
    ASSERT_EQ(result.totalReconstructedSize, 149ULL);
    ASSERT_TRUE(result.confidenceScore >= 90.0);

    // The reconstructed data must pass full format validation
    const auto& sigs = SignatureDatabase::getInstance().getSignatures();
    const FileSignature* jpegSig = nullptr;
    for (const auto& s : sigs) {
        if (s.fileType == "JPEG") { jpegSig = &s; break; }
    }
    ASSERT_TRUE(jpegSig != nullptr);
    auto val = FormatValidator::validate(*jpegSig, result.reconstructedData.data(), result.reconstructedData.size());
    ASSERT_TRUE(val.isValid);
    ASSERT_EQ(val.trueLength, 149ULL);
}

FV_TEST(FragmentAnalysis, UncertaintyHandlingKeepsFragmentsSegregated) {
    std::string imgPath = "test_data/fragmented_evidence.img";
    if (!fs::exists(imgPath)) {
        return;
    }
    DiskImageReader reader(imgPath);
    ASSERT_TRUE(reader.isOpen());

    // Sector 10 contains an orphan header fragment (offset 5120) with no matching footer
    std::vector<uint8_t> orphanHeaderBytes = reader.readBytes(5120, 80);
    FragmentCandidate orphanHeader;
    orphanHeader.fragmentId = 99;
    orphanHeader.offset = 5120;
    orphanHeader.length = 80;
    orphanHeader.startSector = 10;
    orphanHeader.fileType = "JPEG";
    orphanHeader.role = FragmentRole::Header;
    orphanHeader.entropy = CryptoHash::calculateEntropy(orphanHeaderBytes);
    orphanHeader.data = orphanHeaderBytes;
    orphanHeader.confidence = 35.0;

    // Pass empty candidates or unrelated candidates
    std::vector<FragmentCandidate> emptyCandidates;
    auto result = FragmentReconstructor::attemptReconstruction(orphanHeader, emptyCandidates);

    // Must NOT guess or merge arbitrarily
    ASSERT_FALSE(result.isReconstructed);
    ASSERT_TRUE(result.isPartial);
    ASSERT_FALSE(result.uncertaintyReason.empty());
    // Uncertainty reason must explain why fragments were kept segregated
    ASSERT_TRUE(result.uncertaintyReason.find("segregated") != std::string::npos ||
                result.uncertaintyReason.find("No compatible") != std::string::npos);
    ASSERT_EQ(result.totalReconstructedSize, 80ULL);
}
