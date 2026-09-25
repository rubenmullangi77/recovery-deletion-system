#include "reporting/forensic_report.hpp"
#include "forensivault/common/crypto_hash.hpp"
#include <chrono>
#include <sstream>
#include <iomanip>

namespace forensivault {
namespace reporting {

ForensicReportBuilder::ForensicReportBuilder() {
    report_.report_timestamp_iso = logging::AuditLogger::currentTimestampIso();
    
    // Generate a unique report ID
    std::ostringstream ss;
    ss << "REP-" << std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    report_.report_id = ss.str();
}

ForensicReportBuilder& ForensicReportBuilder::setCaseInfo(const core::CaseInfo& info) {
    report_.case_info = info;
    return *this;
}

ForensicReportBuilder& ForensicReportBuilder::setAcquisition(const AcquisitionMetadata& acq) {
    report_.acquisition = acq;
    return *this;
}

ForensicReportBuilder& ForensicReportBuilder::setScanConfig(const ScanConfiguration& config) {
    report_.scan_config = config;
    return *this;
}

ForensicReportBuilder& ForensicReportBuilder::setFilesystem(const FilesystemSummary& fs) {
    report_.filesystem = fs;
    return *this;
}

ForensicReportBuilder& ForensicReportBuilder::setEvidenceHashes(const std::string& preHash, const std::string& postHash) {
    report_.evidence_pre_hash = preHash;
    report_.evidence_post_hash = postHash;
    report_.evidence_unmodified = (!preHash.empty() && preHash == postHash);
    report_.immutability_verification_status = report_.evidence_unmodified ?
        "IMMUTABILITY VERIFIED: Pre-recovery SHA-256 matches post-recovery SHA-256." :
        "INTEGRITY VIOLATION DETECTED: Evidence image hash mismatch!";
    return *this;
}

ForensicReportBuilder& ForensicReportBuilder::addRecoveredItem(const ReportItem& item) {
    report_.recovered_items.push_back(item);
    return *this;
}

ForensicReportBuilder& ForensicReportBuilder::addSanitizationRecord(const SanitizationRecord& san) {
    report_.sanitization_history.push_back(san);
    return *this;
}

ForensicReportBuilder& ForensicReportBuilder::setAuditTrail(const std::vector<logging::AuditEntry>& trail, bool chainVerified) {
    report_.audit_trail = trail;
    report_.audit_entries_count = trail.size();
    report_.audit_chain_verified = chainVerified;
    if (!trail.empty()) {
        report_.latest_blockchain_hash = trail.back().entry_hash;
    }
    return *this;
}

RecoveryStatus ForensicReportBuilder::classifyArtifact(
    const std::string& formatValidationStatus,
    double confidenceScore,
    bool hasStructuralError,
    const std::vector<std::string>& /*warnings*/,
    const std::vector<std::string>& errors) {

    // 1. Structural error or fatal parser failure -> Corrupted
    if (hasStructuralError || !errors.empty() || 
        formatValidationStatus == "INVALID" || formatValidationStatus == "CORRUPTED") {
        return RecoveryStatus::Corrupted;
    }

    // 2. Format explicitly unvalidated -> Unvalidated
    if (formatValidationStatus == "UNVALIDATED") {
        return RecoveryStatus::Unvalidated;
    }

    // 3. Partial validation status or confidence below strict threshold -> PartiallyRecovered
    if (formatValidationStatus == "PARTIAL" || confidenceScore < 70.0) {
        return RecoveryStatus::PartiallyRecovered;
    }

    // 4. Strict validation passed AND high confidence -> SuccessfullyRecovered
    if (formatValidationStatus == "VALID" && confidenceScore >= 70.0) {
        return RecoveryStatus::SuccessfullyRecovered;
    }

    // Conservative default
    return RecoveryStatus::PartiallyRecovered;
}

ForensicReportBuilder& ForensicReportBuilder::loadFromRecovery(
    const core::CaseInfo& caseInfo,
    const core::EvidenceItem& evidence,
    const recovery::RecoveryReport& recReport,
    const std::vector<logging::AuditEntry>& auditTrail) {

    report_.case_info = caseInfo;

    // Acquisition metadata
    report_.acquisition.evidence_id = evidence.evidence_id;
    report_.acquisition.source_path = evidence.filepath;
    report_.acquisition.total_bytes = evidence.size_bytes;
    report_.acquisition.total_sectors = evidence.size_bytes / 512;
    report_.acquisition.sector_size = 512;
    report_.acquisition.intake_sha256 = evidence.sha256_hash;
    report_.acquisition.acquisition_timestamp_iso = evidence.acquired_timestamp_iso;
    report_.acquisition.acquiring_examiner = caseInfo.investigator_name;

    // Hashes & Immutability
    setEvidenceHashes(recReport.evidence_pre_hash, recReport.evidence_post_hash);

    // Filesystem Summary
    std::ostringstream fsOss;
    fsOss << recReport.fs_type;
    report_.filesystem.detected_fs = fsOss.str();
    report_.filesystem.volume_label = recReport.volume_info.volume_label;
    report_.filesystem.cluster_size = recReport.volume_info.cluster_size;
    report_.filesystem.total_clusters = recReport.volume_info.total_clusters;
    report_.filesystem.free_clusters = recReport.volume_info.free_clusters;
    report_.filesystem.active_files_count = recReport.filesystem_active_files.size();
    report_.filesystem.deleted_candidates_count = recReport.filesystem_deleted_files.size();

    // Recovered Items Mapping
    uint64_t nextId = 1;

    // 1. Active Files
    for (const auto& af : recReport.filesystem_active_files) {
        ReportItem item;
        item.item_id = nextId++;
        item.filename = af.filename;
        item.relative_path = "active/" + af.filename;
        item.file_type = af.extension;
        item.extension = af.extension;
        item.byte_offset = af.byte_offset;
        item.sector_offset = af.byte_offset / 512;
        item.size_bytes = af.file_size;
        item.sha256_hash = af.sha256_hash;
        item.recovery_source = "Active Filesystem";
        item.confidence_score = af.confidence_score;
        item.confidence_level = (af.confidence_score >= 80) ? "High" : (af.confidence_score >= 60) ? "Medium" : "Low";
        item.parser_validation_result = af.format_validation_status;
        item.recovery_status = classifyArtifact(af.format_validation_status, af.confidence_score, false, {}, {});
        report_.recovered_items.push_back(item);
    }

    // 2. Deleted Files
    for (const auto& df : recReport.filesystem_deleted_files) {
        ReportItem item;
        item.item_id = nextId++;
        item.filename = df.filename;
        item.relative_path = "deleted/" + df.filename;
        item.file_type = df.extension;
        item.extension = df.extension;
        item.byte_offset = df.byte_offset;
        item.sector_offset = df.byte_offset / 512;
        item.size_bytes = df.file_size;
        item.sha256_hash = df.sha256_hash;
        item.recovery_source = "Deleted Filesystem Entry";
        item.confidence_score = df.confidence_score;
        item.confidence_level = (df.confidence_score >= 80) ? "High" : (df.confidence_score >= 60) ? "Medium" : "Low";
        item.parser_validation_result = df.format_validation_status;
        item.recovery_status = classifyArtifact(df.format_validation_status, df.confidence_score, false, {}, {});
        report_.recovered_items.push_back(item);
    }

    // 3. Raw Carved Files
    for (const auto& cf : recReport.raw_carved_files) {
        ReportItem item;
        item.item_id = nextId++;
        item.filename = "carved_0x" + std::to_string(cf.startOffset) + "." + cf.extension;
        item.relative_path = "carved/" + cf.fileType + "/" + item.filename;
        item.file_type = cf.fileType;
        item.extension = cf.extension;
        item.byte_offset = cf.startOffset;
        item.sector_offset = cf.startOffset / 512;
        item.size_bytes = cf.lengthBytes;
        item.sha256_hash = cf.sha256;
        item.recovery_source = "Raw Signature Carving";
        item.confidence_score = cf.confidenceScore;
        item.confidence_level = cf.confidenceLevel;
        item.parser_validation_result = cf.isValid ? "VALID" : "PARTIAL";
        item.reasons = cf.reasons;
        item.warnings = cf.warnings;
        item.recovery_status = classifyArtifact(
            cf.isValid ? "VALID" : "PARTIAL",
            cf.confidenceScore,
            !cf.isValid,
            cf.warnings,
            {}
        );
        report_.recovered_items.push_back(item);
    }

    // Audit Trail
    setAuditTrail(auditTrail, logging::AuditLogger::getInstance().verifyChain());

    return *this;
}

void ForensicReportBuilder::calculateStatistics() {
    auto& stats = report_.statistics;
    stats.total_artifacts_discovered = report_.recovered_items.size();
    stats.total_bytes_scanned = report_.acquisition.total_bytes;
    stats.total_sectors_scanned = report_.acquisition.total_sectors;

    // Reset counts
    stats.count_successful = 0;
    stats.count_partial = 0;
    stats.count_corrupted = 0;
    stats.count_unvalidated = 0;
    stats.count_not_recoverable = 0;

    stats.bytes_successful = 0;
    stats.bytes_partial = 0;
    stats.bytes_corrupted = 0;
    stats.bytes_unvalidated = 0;

    stats.confidence_very_high = 0;
    stats.confidence_high = 0;
    stats.confidence_medium = 0;
    stats.confidence_low = 0;
    stats.confidence_very_low = 0;

    for (const auto& item : report_.recovered_items) {
        switch (item.recovery_status) {
            case RecoveryStatus::SuccessfullyRecovered:
                stats.count_successful++;
                stats.bytes_successful += item.size_bytes;
                break;
            case RecoveryStatus::PartiallyRecovered:
                stats.count_partial++;
                stats.bytes_partial += item.size_bytes;
                break;
            case RecoveryStatus::Corrupted:
                stats.count_corrupted++;
                stats.bytes_corrupted += item.size_bytes;
                break;
            case RecoveryStatus::Unvalidated:
                stats.count_unvalidated++;
                stats.bytes_unvalidated += item.size_bytes;
                break;
            case RecoveryStatus::NotRecoverable:
                stats.count_not_recoverable++;
                break;
        }

        if (item.confidence_score >= 95.0) stats.confidence_very_high++;
        else if (item.confidence_score >= 80.0) stats.confidence_high++;
        else if (item.confidence_score >= 60.0) stats.confidence_medium++;
        else if (item.confidence_score >= 40.0) stats.confidence_low++;
        else stats.confidence_very_low++;
    }
}

ForensicReport ForensicReportBuilder::build() {
    calculateStatistics();
    return report_;
}

} // namespace reporting
} // namespace forensivault
