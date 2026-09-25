#include "carving/file_carver.hpp"
#include "carving/confidence_scorer.hpp"
#include "core/binary_utils.hpp"
#include "forensivault/common/crypto_hash.hpp"
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <iostream>

namespace fs = std::filesystem;

namespace forensivault::carving {

FileCarver::FileCarver(CarverOptions options)
    : options_(std::move(options)) {}

std::string FileCarver::generateUniqueFilename(uint64_t id, 
                                               const std::string& ext, 
                                               const std::string& subfolder) {
    fs::path targetDir = options_.outputDirectory;
    if (options_.organizeByType && !subfolder.empty()) {
        targetDir /= subfolder;
    }
    fs::create_directories(targetDir);

    std::ostringstream filename;
    filename << "FILE_" << std::setfill('0') << std::setw(6) << id 
             << "." << ext;

    return (targetDir / filename.str()).string();
}

std::optional<CarvedFile> FileCarver::carveSingle(core::DiskImageReader& reader,
                                                  const SignatureMatch& match,
                                                  uint64_t nextMatchOffset) {
    if (!match.signature) return std::nullopt;

    const FileSignature& sig = *match.signature;
    const uint64_t imageSize = reader.size();
    if (match.offset >= imageSize) return std::nullopt;

    // Calculate maximum available bytes from this offset
    uint64_t availableBytes = imageSize - match.offset;
    uint64_t maxSearchWindow = std::min(availableBytes, std::min(sig.maxReasonableSize, options_.maxCarveSize));

    if (maxSearchWindow < sig.minSize) {
        return std::nullopt;
    }

    // Read candidate window into memory for parsing
    std::vector<uint8_t> candidateBuffer = reader.readBytes(match.offset, static_cast<size_t>(maxSearchWindow));
    if (candidateBuffer.empty()) {
        return std::nullopt;
    }

    // Run format-specific structural validation
    FormatValidationDetails val = FormatValidator::validate(sig, candidateBuffer.data(), candidateBuffer.size());

    // If validation determined a concrete boundary length, truncate buffer
    uint64_t carveLength = val.trueLength;
    if (carveLength == 0 || carveLength > candidateBuffer.size()) {
        if (nextMatchOffset > match.offset && nextMatchOffset < match.offset + candidateBuffer.size()) {
            // Bound at next file header if known
            carveLength = nextMatchOffset - match.offset;
        } else {
            carveLength = std::min<uint64_t>(candidateBuffer.size(), 4096);
        }
    }

    // Truncate candidate buffer to actual carved length
    if (carveLength < candidateBuffer.size()) {
        candidateBuffer.resize(static_cast<size_t>(carveLength));
    }

    // Reject invalid candidates immediately
    if (val.validationState == "INVALID" || val.confidenceScore < options_.minimumConfidence) {
        return std::nullopt;
    }

    // Evaluate explainable forensic confidence score
    auto eval = RecoveryConfidenceScorer::evaluate(
        0, val.classifiedType, match.offset, candidateBuffer.data(), candidateBuffer.size());

    CarvedFile file;
    file.id = 0; // Set by session
    file.fileType = val.classifiedType;
    file.extension = val.classifiedExtension;
    file.mimeType = val.classifiedMime;
    file.startOffset = match.offset;
    file.lengthBytes = carveLength;
    file.startSector = match.sector;
    file.sectorSpan = core::BinaryUtils::calculateSectorSpan(match.offset, carveLength, reader.sectorSize());
    file.hasValidHeader = (eval.breakdown.headerScore > 0);
    file.hasValidFooter = (eval.breakdown.footerScore > 0);
    file.isValid = val.isValid;
    file.validationState = val.validationState;
    file.recoveryMethod = "Raw Signature Carving";
    file.confidenceScore = eval.confidenceScore;
    file.confidenceLevel = confidenceLevelToString(eval.confidenceLevel);
    file.validationNotes = val.notes;
    file.reasons = eval.reasons;
    file.warnings = eval.warnings;

    // Extract to disk if requested and compute SHA-256 directly from output disk file
    if (options_.extractFiles) {
        // Folder name: JPG, PNG, PDF, ZIP, etc.
        std::string folderName = file.fileType;
        if (folderName == "JPEG") folderName = "JPG";

        std::string outPath = generateUniqueFilename(match.offset, file.extension, folderName);
        std::ofstream outFile(outPath, std::ios::binary | std::ios::trunc);
        if (outFile) {
            outFile.write(reinterpret_cast<const char*>(candidateBuffer.data()), candidateBuffer.size());
            outFile.close();
            file.recoveredFilePath = outPath;

            // Re-read physical output file directly from disk to compute authentic SHA-256
            std::ifstream inFile(outPath, std::ios::binary);
            if (inFile) {
                std::vector<uint8_t> diskData((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
                file.sha256 = CryptoHash::sha256(diskData.data(), diskData.size());
            } else {
                file.sha256 = core::BinaryUtils::sha256(candidateBuffer);
            }
        } else {
            file.sha256 = core::BinaryUtils::sha256(candidateBuffer);
        }
    } else {
        file.sha256 = core::BinaryUtils::sha256(candidateBuffer);
    }

    return file;
}

CarvingSessionResult FileCarver::carve(core::DiskImageReader& reader,
                                       ScanProgressCallback progress) {
    CarvingSessionResult session;
    session.imagePath = reader.filepath();
    session.totalBytesScanned = reader.size();
    session.totalSectorsScanned = reader.totalSectors();

    auto startTime = std::chrono::high_resolution_clock::now();

    // Step 1: Scan for all signature matches
    SignatureScanner scanner(db_);
    std::vector<SignatureMatch> matches = scanner.scan(reader, progress);
    session.signaturesDiscovered = matches.size();

    // Step 2: Carve, bound, validate, and extract each candidate
    uint64_t fileIdCounter = 1;
    uint64_t lastCarvedEndOffset = 0;

    for (size_t i = 0; i < matches.size(); ++i) {
        const auto& m = matches[i];

        // Skip if this match is entirely inside a previously carved valid container (e.g. inside a ZIP/DOCX)
        if (m.offset < lastCarvedEndOffset) {
            continue;
        }

        uint64_t nextOffset = (i + 1 < matches.size()) ? matches[i + 1].offset : 0;
        auto carved = carveSingle(reader, m, nextOffset);

        if (carved.has_value()) {
            carved->id = fileIdCounter++;
            if (carved->isValid) {
                session.validFilesCount++;
                lastCarvedEndOffset = std::max(lastCarvedEndOffset, carved->startOffset + carved->lengthBytes);
            } else {
                session.partialFilesCount++;
            }
            session.filesSuccessfullyCarved++;
            session.carvedFiles.push_back(*carved);
        }
    }

    auto endTime = std::chrono::high_resolution_clock::now();
    session.durationMilliseconds = std::chrono::duration<double, std::milli>(endTime - startTime).count();

    return session;
}

} // namespace forensivault::carving
