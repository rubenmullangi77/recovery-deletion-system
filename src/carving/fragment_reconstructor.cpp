#include "carving/fragment_reconstructor.hpp"
#include "carving/format_validator.hpp"
#include "core/binary_utils.hpp"
#include "forensivault/common/crypto_hash.hpp"
#include <algorithm>
#include <cstring>
#include <iostream>
#include <sstream>
#include <iomanip>

namespace forensivault::carving {

FragmentReconstructor::FragmentReconstructor([[maybe_unused]] uint32_t clusterSize) {}

bool FragmentReconstructor::evaluateCompatibility(const FragmentCandidate& first,
                                                  const FragmentCandidate& second) {
    // Basic criteria: types must match or be compatible
    if (first.fileType != second.fileType) {
        return false;
    }

    // Role sequence: Header must precede Body or Footer; Body must precede Footer
    if (first.role == FragmentRole::Header && second.role == FragmentRole::Header) return false;
    if (first.role == FragmentRole::Footer) return false;
    if (second.role == FragmentRole::Header) return false;

    // Offset sequence: Second fragment must physically follow the first
    if (second.offset <= first.offset + first.length) {
        return false;
    }

    // Entropy compatibility check
    // If first has high entropy (e.g. compressed JPEG/PNG scan data) and second is all zeroes, not compatible
    if (first.entropy > 5.0 && second.entropy < 0.5) {
        return false;
    }

    return true;
}

std::vector<FragmentCandidate> FragmentReconstructor::findOrphanFragments(
    const std::string& targetType,
    const uint8_t* imageBuffer,
    uint64_t bufferBaseOffset,
    size_t bufferLength,
    uint32_t clusterSize) {

    std::vector<FragmentCandidate> orphans;
    if (!imageBuffer || bufferLength < clusterSize || clusterSize == 0) {
        return orphans;
    }

    uint64_t fragIdCounter = 1;

    // Scan cluster by cluster
    for (size_t offset = 0; offset + clusterSize <= bufferLength; offset += clusterSize) {
        const uint8_t* clusterData = imageBuffer + offset;
        uint64_t absOffset = bufferBaseOffset + offset;
        double ent = CryptoHash::calculateEntropy(clusterData, clusterSize);

        // Skip completely uniform clusters (e.g. 0x00 or 0xFF wiped space)
        if (ent < 0.1) {
            continue;
        }

        if (targetType == "JPEG") {
            // Check if this cluster contains an EOI marker (0xFF 0xD9)
            int64_t eoiPos = -1;
            for (size_t i = 0; i + 1 < clusterSize; ++i) {
                if (clusterData[i] == 0xFF && clusterData[i + 1] == 0xD9) {
                    eoiPos = static_cast<int64_t>(i + 2);
                }
            }

            if (eoiPos > 0) {
                // Orphan Footer fragment found
                FragmentCandidate frag;
                frag.fragmentId = fragIdCounter++;
                frag.offset = absOffset;
                frag.length = static_cast<uint64_t>(eoiPos);
                frag.startSector = core::BinaryUtils::byteToSector(absOffset, 512);
                frag.fileType = "JPEG";
                frag.role = FragmentRole::Footer;
                frag.data.assign(clusterData, clusterData + eoiPos);
                frag.entropy = CryptoHash::calculateEntropy(frag.data);
                frag.structuralCompatibility = true;
                frag.confidence = 75.0;
                frag.diagnosticNotes = "Orphan JPEG footer cluster containing valid EOI (0xFFD9) marker";
                orphans.push_back(frag);
            } else if (ent > 5.0) {
                // Potential high-entropy JPEG scan body fragment
                FragmentCandidate frag;
                frag.fragmentId = fragIdCounter++;
                frag.offset = absOffset;
                frag.length = clusterSize;
                frag.startSector = core::BinaryUtils::byteToSector(absOffset, 512);
                frag.fileType = "JPEG";
                frag.role = FragmentRole::Body;
                frag.entropy = ent;
                frag.structuralCompatibility = true;
                frag.confidence = 50.0;
                frag.data.assign(clusterData, clusterData + clusterSize);
                frag.diagnosticNotes = "JPEG continuation body cluster with consistent entropy";
                orphans.push_back(frag);
            }
        } else if (targetType == "PNG") {
            // Check for IEND chunk (49 45 4E 44 AE 42 60 82)
            const uint8_t iendPattern[] = {0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82};
            int64_t iendPos = core::BinaryUtils::findFirst(clusterData, clusterSize, iendPattern, 8);
            if (iendPos >= 4) { // Length field precedes IEND
                size_t endOffset = static_cast<size_t>(iendPos) + 8;
                FragmentCandidate frag;
                frag.fragmentId = fragIdCounter++;
                frag.offset = absOffset;
                frag.length = endOffset;
                frag.startSector = core::BinaryUtils::byteToSector(absOffset, 512);
                frag.fileType = "PNG";
                frag.role = FragmentRole::Footer;
                frag.entropy = ent;
                frag.structuralCompatibility = true;
                frag.confidence = 85.0;
                frag.data.assign(clusterData, clusterData + endOffset);
                frag.diagnosticNotes = "Orphan PNG footer cluster containing verified IEND chunk and CRC";
                orphans.push_back(frag);
            }
        } else if (targetType == "ZIP" || targetType == "DOCX" || targetType == "XLSX" || targetType == "PPTX") {
            // Check for EOCD record (50 4B 05 06)
            for (size_t i = 0; i + 22 <= clusterSize; ++i) {
                if (clusterData[i] == 0x50 && clusterData[i + 1] == 0x4B && clusterData[i + 2] == 0x05 && clusterData[i + 3] == 0x06) {
                    uint16_t commentLen = static_cast<uint16_t>(clusterData[i + 20]) |
                                         (static_cast<uint16_t>(clusterData[i + 21]) << 8);
                    if (i + 22 + commentLen <= clusterSize) {
                        size_t eocdEnd = i + 22 + commentLen;
                        FragmentCandidate frag;
                        frag.fragmentId = fragIdCounter++;
                        frag.offset = absOffset;
                        frag.length = eocdEnd;
                        frag.startSector = core::BinaryUtils::byteToSector(absOffset, 512);
                        frag.fileType = targetType;
                        frag.role = FragmentRole::Footer;
                        frag.entropy = ent;
                        frag.structuralCompatibility = true;
                        frag.confidence = 80.0;
                        frag.data.assign(clusterData, clusterData + eocdEnd);
                        frag.diagnosticNotes = "Orphan ZIP/Office Central Directory footer cluster";
                        orphans.push_back(frag);
                        break;
                    }
                }
            }
        }
    }

    return orphans;
}

ReconstructionResult FragmentReconstructor::attemptReconstruction(
    const FragmentCandidate& headerFrag,
    const std::vector<FragmentCandidate>& candidates,
    uint64_t maxGapBytes) {

    ReconstructionResult result;
    result.fileType = headerFrag.fileType;
    result.fragmentOffsets.push_back(headerFrag.offset);

    // Initial check: if headerFrag is already complete standalone, no reconstruction needed
    if (headerFrag.role == FragmentRole::Standalone) {
        result.isReconstructed = true;
        result.isPartial = false;
        result.totalReconstructedSize = headerFrag.length;
        result.reconstructedData = headerFrag.data;
        result.confidenceScore = headerFrag.confidence;
        result.sha256 = core::BinaryUtils::sha256(result.reconstructedData);
        return result;
    }

    // Filter candidates by type and order by offset
    std::vector<FragmentCandidate> eligible;
    for (const auto& c : candidates) {
        if (evaluateCompatibility(headerFrag, c)) {
            uint64_t gap = c.offset - (headerFrag.offset + headerFrag.length);
            if (gap <= maxGapBytes) {
                eligible.push_back(c);
            }
        }
    }

    if (eligible.empty()) {
        result.isReconstructed = false;
        result.isPartial = true;
        result.uncertaintyReason = "No compatible continuation fragments found within gap boundary (" +
                                  std::to_string(maxGapBytes) + " bytes); fragments kept segregated";
        result.reconstructedData = headerFrag.data;
        result.totalReconstructedSize = headerFrag.length;
        result.confidenceScore = std::min(headerFrag.confidence, 45.0);
        result.sha256 = core::BinaryUtils::sha256(result.reconstructedData);
        return result;
    }

    // Sort eligible by offset ascending
    std::sort(eligible.begin(), eligible.end(), [](const FragmentCandidate& a, const FragmentCandidate& b) {
        return a.offset < b.offset;
    });

    // Conservative strategy:
    // Try concatenating header with candidate fragments and test whether format validation passes
    for (const auto& footerCandidate : eligible) {
        std::vector<uint8_t> trialData = headerFrag.data;
        trialData.insert(trialData.end(), footerCandidate.data.begin(), footerCandidate.data.end());

        // Get signature definition from database
        const auto& sigs = SignatureDatabase::getInstance().getSignatures();
        const FileSignature* matchingSig = nullptr;
        for (const auto& s : sigs) {
            if (s.fileType == headerFrag.fileType) {
                matchingSig = &s;
                break;
            }
        }

        if (!matchingSig) continue;

        // Perform strict format validation
        FormatValidationDetails val = FormatValidator::validate(*matchingSig, trialData.data(), trialData.size());

        if (val.isValid) {
            // Also evaluate confidence score
            auto conf = RecoveryConfidenceScorer::evaluate(0, headerFrag.fileType, headerFrag.offset, 
                                                           trialData.data(), trialData.size());

            if (conf.confidenceScore >= 80) {
                // Successful verified reconstruction!
                result.isReconstructed = true;
                result.isPartial = false;
                result.fragmentOffsets.push_back(footerCandidate.offset);
                result.totalReconstructedSize = trialData.size();
                result.reconstructedData = std::move(trialData);
                result.confidenceScore = conf.confidenceScore;
                result.sha256 = core::BinaryUtils::sha256(result.reconstructedData);
                std::ostringstream reasonStream;
                reasonStream << "Successfully reconstructed from 2 disjoint fragments (Offsets: 0x"
                             << std::hex << headerFrag.offset << ", 0x" << footerCandidate.offset
                             << ") and verified via structural parser";
                result.uncertaintyReason = reasonStream.str();
                return result;
            }
        }
    }

    // If we reach here, none of the combinations produced a clean valid format
    result.isReconstructed = false;
    result.isPartial = true;
    result.uncertaintyReason = "Candidate fragments exist but failed strict format validation; kept segregated to avoid false recovery";
    result.reconstructedData = headerFrag.data;
    result.totalReconstructedSize = headerFrag.length;
    result.confidenceScore = 35.0; // Marked as partial/low confidence
    result.sha256 = core::BinaryUtils::sha256(result.reconstructedData);
    return result;
}

} // namespace forensivault::carving
