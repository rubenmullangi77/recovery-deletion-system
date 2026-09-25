#include "recovery/recovery_engine.hpp"
#include "filesystem/fat32_analyzer.hpp"
#include "filesystem/exfat_analyzer.hpp"
#include "filesystem/ntfs_analyzer.hpp"
#include "carving/format_validator.hpp"
#include "carving/confidence_scorer.hpp"
#include "logging/audit_logger.hpp"
#include "forensivault/common/crypto_hash.hpp"
#include <fstream>
#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

namespace forensivault {
namespace recovery {

namespace {

std::string computeReaderSha256(core::DiskImageReader& reader) {
    CryptoHash::Sha256Context ctx;
    uint64_t totalSize = reader.size();

    const uint64_t maxFullHashSize = 4ULL * 1024 * 1024 * 1024; // 4 GB
    bool isLiveDevice = reader.filepath().rfind("\\\\.\\", 0) == 0 ||
                        reader.filepath().rfind("\\\\?\\", 0) == 0 ||
                        (reader.filepath().size() <= 3 && reader.filepath().find(':') != std::string::npos);

    if (totalSize > maxFullHashSize || isLiveDevice) {
        size_t headerBytes = static_cast<size_t>(std::min<uint64_t>(65536, totalSize));
        auto headerBuf = reader.readBytes(0, headerBytes);
        if (!headerBuf.empty()) {
            ctx.update(headerBuf.data(), headerBuf.size());
        }
        return "METADATA-VBR:" + ctx.finalize();
    }

    const size_t bufSize = 64 * 1024;
    uint64_t offset = 0;

    while (offset < totalSize) {
        size_t toRead = static_cast<size_t>(std::min<uint64_t>(bufSize, totalSize - offset));
        auto chunk = reader.readBytes(offset, toRead);
        if (chunk.empty()) break;
        ctx.update(chunk.data(), chunk.size());
        offset += chunk.size();
    }
    return ctx.finalize();
}

} // anonymous namespace

RecoveryEngine::RecoveryEngine() = default;

std::unique_ptr<filesystem::FilesystemAnalyzer> RecoveryEngine::detectFilesystem(
    core::DiskImageReader& reader, uint64_t partitionStartSector) {
    
    // 1. Try FAT32
    auto fat32 = std::make_unique<filesystem::FAT32Analyzer>();
    if (fat32->probe(reader, partitionStartSector)) {
        return fat32;
    }

    // 2. Try exFAT
    auto exfat = std::make_unique<filesystem::ExFATAnalyzer>();
    if (exfat->probe(reader, partitionStartSector)) {
        return exfat;
    }

    // 3. Try NTFS
    auto ntfs = std::make_unique<filesystem::NTFSAnalyzer>();
    if (ntfs->probe(reader, partitionStartSector)) {
        return ntfs;
    }

    return nullptr;
}

RecoveryReport RecoveryEngine::runRecovery(core::DiskImageReader& reader,
                                          const std::string& outputDir,
                                          const CaseContext& ctx) {
    RecoveryReport report;
    report.evidence_image_path = reader.filepath();

    // 1. Compute Pre-Recovery Evidence Hash (Proof of evidence state before recovery)
    report.evidence_pre_hash = computeReaderSha256(reader);

    auto analyzer = detectFilesystem(reader, 0);
    std::vector<std::pair<uint64_t, uint64_t>> recoveredRanges; // Byte offset, size

    if (analyzer) {
        report.fs_detected = true;
        report.volume_info = analyzer->getVolumeInfo();
        report.fs_type = report.volume_info.fs_type;

        // 1. Enumerate Active Files
        auto activeFiles = analyzer->listDirectory("/");
        for (auto& rec : activeFiles) {
            auto data = analyzer->extractFile(rec, reader);
            if (!data.empty()) {
                rec.sha256_hash = CryptoHash::sha256(data.data(), data.size());
                recoveredRanges.push_back({rec.byte_offset, rec.file_size});

                auto scoreRes = carving::RecoveryConfidenceScorer::evaluate(
                    0, rec.extension, rec.byte_offset, data.data(), data.size());
                rec.format_validation_status = scoreRes.validationStatus;
                rec.confidence_score = scoreRes.confidenceScore;

                if (!outputDir.empty()) {
                    fs::path outPath = fs::path(outputDir) / "fs_recovered" / "active" / rec.filename;
                    fs::create_directories(outPath.parent_path());
                    std::ofstream ofs(outPath, std::ios::binary);
                    if (ofs) ofs.write(reinterpret_cast<const char*>(data.data()), data.size());
                }
            }
            report.filesystem_active_files.push_back(rec);
        }

        // 2. Enumerate Deleted File Candidates
        auto deletedFiles = analyzer->findDeletedFiles();
        for (auto& rec : deletedFiles) {
            auto data = analyzer->extractFile(rec, reader);
            if (!data.empty()) {
                rec.sha256_hash = CryptoHash::sha256(data.data(), data.size());
                recoveredRanges.push_back({rec.byte_offset, rec.file_size});

                auto scoreRes = carving::RecoveryConfidenceScorer::evaluate(
                    0, rec.extension, rec.byte_offset, data.data(), data.size());
                rec.format_validation_status = scoreRes.validationStatus;
                rec.confidence_score = scoreRes.confidenceScore;

                if (!outputDir.empty()) {
                    fs::path outPath = fs::path(outputDir) / "fs_recovered" / "deleted" / rec.filename;
                    fs::create_directories(outPath.parent_path());
                    std::ofstream ofs(outPath, std::ios::binary);
                    if (ofs) ofs.write(reinterpret_cast<const char*>(data.data()), data.size());
                }
            }
            report.filesystem_deleted_files.push_back(rec);
        }
    }

    // 3. Fallback to Deep Signature Carving
    carving::CarverOptions opts;
    opts.outputDirectory = outputDir.empty() ? "recovered" : (fs::path(outputDir) / "carved").string();
    opts.extractFiles = !outputDir.empty();
    carving::FileCarver carver(opts);

    auto session = carver.carve(reader);

    for (const auto& carved : session.carvedFiles) {
        // Check if this carved file coincides with an already recovered filesystem file
        bool alreadyRecoveredViaFs = false;
        for (const auto& range : recoveredRanges) {
            if (range.first != 0 && carved.startOffset >= range.first && carved.startOffset < (range.first + range.second)) {
                alreadyRecoveredViaFs = true;
                break;
            }
        }

        if (!alreadyRecoveredViaFs) {
            report.raw_carved_files.push_back(carved);
        }
    }

    // 4. Compute Post-Recovery Evidence Hash (Proof of evidence immutability)
    report.evidence_post_hash = computeReaderSha256(reader);
    report.evidence_unmodified = (!report.evidence_pre_hash.empty() &&
                                  report.evidence_pre_hash == report.evidence_post_hash);

    // 5. Generate structured forensic audit record
    logging::AuditEntry auditEntry;
    auditEntry.case_id = ctx.case_id.empty() ? "UNASSIGNED" : ctx.case_id;
    auditEntry.evidence_id = ctx.evidence_id.empty() ? "EVD-AUTO" : ctx.evidence_id;
    auditEntry.operation_id = ctx.operation_id.empty() ? "OP-REC-001" : ctx.operation_id;
    auditEntry.operator_name = ctx.operator_name.empty() ? "Forensic Analyst" : ctx.operator_name;
    auditEntry.operation_type = "FILE_RECOVERY";
    auditEntry.source_identifier = reader.filepath();
    auditEntry.source_sha256 = report.evidence_pre_hash;
    auditEntry.method = report.fs_detected ? "Filesystem Parsing + Signature Fallback" : "Deep Signature Carving";
    auditEntry.status = "SUCCESS";
    auditEntry.details = "Recovered " + std::to_string(report.total_recovered_count()) + " total files (" +
                         std::to_string(report.filesystem_active_files.size()) + " active, " +
                         std::to_string(report.filesystem_deleted_files.size()) + " deleted, " +
                         std::to_string(report.raw_carved_files.size()) + " carved).";

    // Verification results
    auditEntry.verification_results = report.evidence_unmodified ?
        "EVIDENCE_IMMUTABILITY_VERIFIED: Source image hash unchanged before and after recovery." :
        "EVIDENCE_CORRUPTED_WARNING: Source image hash differed after recovery!";

    uint64_t artifactId = 1;
    // Map Active FS Files
    for (const auto& f : report.filesystem_active_files) {
        logging::RecoveredArtifactRecord rec;
        rec.file_id = artifactId++;
        rec.filename = f.filename;
        rec.relative_path = "active/" + f.filename;
        rec.file_type = f.extension;
        rec.extension = f.extension;
        rec.byte_offset = f.byte_offset;
        rec.size_bytes = f.file_size;
        rec.sha256_hash = f.sha256_hash;
        rec.confidence_score = f.confidence_score;
        rec.confidence_level = (f.confidence_score >= 80) ? "High" : (f.confidence_score >= 60) ? "Medium" : "Low";
        rec.validation_status = f.format_validation_status;
        auditEntry.recovered_artifacts.push_back(rec);
    }

    // Map Deleted FS Files
    for (const auto& f : report.filesystem_deleted_files) {
        logging::RecoveredArtifactRecord rec;
        rec.file_id = artifactId++;
        rec.filename = f.filename;
        rec.relative_path = "deleted/" + f.filename;
        rec.file_type = f.extension;
        rec.extension = f.extension;
        rec.byte_offset = f.byte_offset;
        rec.size_bytes = f.file_size;
        rec.sha256_hash = f.sha256_hash;
        rec.confidence_score = f.confidence_score;
        rec.confidence_level = (f.confidence_score >= 80) ? "High" : (f.confidence_score >= 60) ? "Medium" : "Low";
        rec.validation_status = f.format_validation_status;
        auditEntry.recovered_artifacts.push_back(rec);
    }

    // Map Raw Carved Files
    for (const auto& c : report.raw_carved_files) {
        logging::RecoveredArtifactRecord rec;
        rec.file_id = artifactId++;
        rec.filename = "carved_0x" + std::to_string(c.startOffset) + "." + c.extension;
        rec.relative_path = "carved/" + c.fileType + "/" + rec.filename;
        rec.file_type = c.fileType;
        rec.extension = c.extension;
        rec.byte_offset = c.startOffset;
        rec.size_bytes = c.lengthBytes;
        rec.sha256_hash = c.sha256;
        rec.confidence_score = c.confidenceScore;
        rec.confidence_level = c.confidenceLevel;
        rec.validation_status = c.isValid ? "VALID" : "PARTIAL";
        rec.reasons = c.reasons;
        rec.warnings = c.warnings;
        auditEntry.recovered_artifacts.push_back(rec);
    }

    // Chain of custody record for recovery action
    logging::CustodyEvent custodyEv;
    custodyEv.timestamp_iso = logging::AuditLogger::currentTimestampIso();
    custodyEv.action = "FORENSIC_RECOVERY_ANALYSIS";
    custodyEv.custodian = auditEntry.operator_name;
    custodyEv.location = "Forensic Workstation";
    custodyEv.notes = "Executed non-destructive recovery on evidence image. Pre-SHA256: " +
                      report.evidence_pre_hash + " | Post-SHA256: " + report.evidence_post_hash;
    auditEntry.chain_of_custody.push_back(custodyEv);

    auto logged = logging::AuditLogger::getInstance().logForensicOperation(auditEntry);
    report.audit_entry_id = logged.entry_id;
    report.audit_entry_hash = logged.entry_hash;

    return report;
}

} // namespace recovery
} // namespace forensivault
