#pragma once

#include "carving/file_signature.hpp"
#include "carving/confidence_scorer.hpp"
#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include <optional>

namespace forensivault::carving {

/**
 * @brief Classification of a file fragment based on internal file anatomy.
 */
enum class FragmentRole {
    Header,     // Contains file start signature / metadata header
    Body,       // Continuation cluster / payload stream without explicit start or end
    Footer,     // Terminating cluster containing EOF / EOCD / IEND
    Standalone  // Self-contained contiguous file
};

inline std::string fragmentRoleToString(FragmentRole role) {
    switch (role) {
        case FragmentRole::Header:     return "Header";
        case FragmentRole::Body:       return "Body";
        case FragmentRole::Footer:     return "Footer";
        case FragmentRole::Standalone: return "Standalone";
        default: return "Unknown";
    }
}

/**
 * @brief Represents a discovered candidate fragment in unallocated space or slack.
 */
struct FragmentCandidate {
    uint64_t fragmentId{0};
    uint64_t offset{0};
    uint64_t length{0};
    uint64_t startSector{0};
    std::string fileType;               // e.g. "JPEG", "PNG", "PDF", "ZIP"
    FragmentRole role{FragmentRole::Body};
    double entropy{0.0};                // Shannon entropy of fragment data
    bool structuralCompatibility{false};
    double confidence{0.0};             // 0 - 100%
    std::vector<uint8_t> data;          // Fragment payload cached for stitching
    std::string diagnosticNotes;
};

/**
 * @brief Result of attempting to reconstruct fragments into a contiguous stream.
 */
struct ReconstructionResult {
    bool isReconstructed{false};
    bool isPartial{false};              // True if fragments remain unresolved or uncertain
    std::string fileType;
    std::vector<uint64_t> fragmentOffsets;
    uint64_t totalReconstructedSize{0};
    double confidenceScore{0.0};
    std::string uncertaintyReason;      // Explainable reason why fragments could or could not be joined
    std::vector<uint8_t> reconstructedData;
    std::string sha256;
};

/**
 * @brief Conservative Fragment Reconstructor.
 * Identifies disjoint fragments, tests boundary and structural compatibility,
 * and only merges if full format-specific validation passes.
 * If uncertain, fragments are left segregated and marked partial.
 */
class FragmentReconstructor {
public:
    explicit FragmentReconstructor(uint32_t clusterSize = 4096);

    /**
     * @brief Analyze a candidate header fragment and look for orphan body/footer fragments.
     * @param headerFrag The primary header fragment with missing footer.
     * @param candidates Pool of other unallocated or trailing fragments.
     * @return ReconstructionResult detailing whether clean assembly succeeded or uncertainty remains.
     */
    static ReconstructionResult attemptReconstruction(
        const FragmentCandidate& headerFrag,
        const std::vector<FragmentCandidate>& candidates,
        uint64_t maxGapBytes = 1024 * 1024); // Conservative search window (default 1MB gap)

    /**
     * @brief Evaluates whether two adjacent fragments exhibit structural compatibility.
     */
    static bool evaluateCompatibility(const FragmentCandidate& first,
                                     const FragmentCandidate& second);

    /**
     * @brief Scans a disk image byte slice to detect orphan footers or body continuation clusters.
     */
    static std::vector<FragmentCandidate> findOrphanFragments(
        const std::string& targetType,
        const uint8_t* imageBuffer,
        uint64_t bufferBaseOffset,
        size_t bufferLength,
        uint32_t clusterSize = 512);
};

} // namespace forensivault::carving
