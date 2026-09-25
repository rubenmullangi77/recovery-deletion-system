#pragma once

#include "forensivault/common/types.hpp"
#include "logging/audit_logger.hpp"
#include "core/case_manager.hpp"
#include <string>
#include <vector>
#include <cstdint>
#include <sstream>
#include <iomanip>

namespace forensivault {
namespace reporting {

/**
 * @brief Strict forensic recovery status classification.
 * Enforces: Do not claim successful recovery unless format parser validation confirms it.
 */
enum class RecoveryStatus {
    SuccessfullyRecovered,  ///< Valid header, structure, footer/CRC passed, confidence >= 70%
    PartiallyRecovered,     ///< Truncated stream, missing footer marker, or conservative fragment assembly
    Corrupted,              ///< Signature matched but internal structure invalid, CRC mismatch, or parse failure
    Unvalidated,            ///< File type without active structural parser validator
    NotRecoverable          ///< Overwritten clusters or zeroed target area
};

inline std::string recoveryStatusToString(RecoveryStatus s) {
    switch (s) {
        case RecoveryStatus::SuccessfullyRecovered: return "Successfully Recovered";
        case RecoveryStatus::PartiallyRecovered:    return "Partially Recovered";
        case RecoveryStatus::Corrupted:             return "Corrupted";
        case RecoveryStatus::Unvalidated:           return "Unvalidated";
        case RecoveryStatus::NotRecoverable:        return "Not Recoverable";
    }
    return "Unknown";
}

inline std::string recoveryStatusCode(RecoveryStatus s) {
    switch (s) {
        case RecoveryStatus::SuccessfullyRecovered: return "SUCCESS";
        case RecoveryStatus::PartiallyRecovered:    return "PARTIAL";
        case RecoveryStatus::Corrupted:             return "CORRUPTED";
        case RecoveryStatus::Unvalidated:           return "UNVALIDATED";
        case RecoveryStatus::NotRecoverable:        return "NOT_RECOVERABLE";
    }
    return "UNKNOWN";
}

/**
 * @brief Detailed report entry for an individual discovered or recovered artifact.
 */
struct ReportItem {
    uint64_t item_id = 0;
    std::string filename;
    std::string relative_path;
    std::string file_type;
    std::string extension;
    std::string mime_type;
    uint64_t byte_offset = 0;
    uint64_t sector_offset = 0;
    uint64_t size_bytes = 0;
    std::string sha256_hash;
    std::string md5_hash;
    std::string recovery_source; // "Active Filesystem", "Deleted Filesystem", "Raw Signature Carving"
    
    // Confidence & Forensic Validation
    double confidence_score = 0.0;
    std::string confidence_level;
    RecoveryStatus recovery_status = RecoveryStatus::Unvalidated;
    std::string parser_validation_result;
    
    std::vector<std::string> reasons;
    std::vector<std::string> warnings;
    std::vector<std::string> errors;

    std::string offsetHex() const {
        std::ostringstream ss;
        ss << "0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << byte_offset;
        return ss.str();
    }
};

/**
 * @brief Scan configuration parameters used during acquisition/recovery.
 */
struct ScanConfiguration {
    std::vector<std::string> enabled_signatures;
    uint32_t cluster_size = 4096;
    uint64_t min_file_size = 16;
    uint64_t max_file_size = 50 * 1024 * 1024; // 50 MB default
    bool fragmented_reconstruction_enabled = true;
    bool active_fs_scan_enabled = true;
    bool deleted_fs_scan_enabled = true;
    bool raw_carving_fallback_enabled = true;
    std::vector<std::string> filesystem_analyzers = {"FAT32", "exFAT", "NTFS"};
};

/**
 * @brief Evidence acquisition and storage geometry metadata.
 */
struct AcquisitionMetadata {
    std::string evidence_id;
    std::string source_path;
    std::string image_format = "Raw Forensic Image (.img / .dd)";
    uint64_t total_bytes = 0;
    uint32_t sector_size = 512;
    uint64_t total_sectors = 0;
    bool has_mbr_signature = false;
    std::string intake_sha256;
    std::string intake_md5;
    std::string acquisition_timestamp_iso;
    std::string acquiring_examiner;
};

/**
 * @brief Volume and filesystem analysis summary.
 */
struct FilesystemSummary {
    std::string detected_fs = "None / Damaged";
    std::string volume_label;
    uint32_t cluster_size = 0;
    uint64_t total_clusters = 0;
    uint64_t free_clusters = 0;
    uint64_t active_files_count = 0;
    uint64_t deleted_candidates_count = 0;
    std::string partition_table_status;
};

/**
 * @brief Recovery process statistics and confidence breakdown.
 */
struct RecoveryStatistics {
    uint64_t total_bytes_scanned = 0;
    uint64_t total_sectors_scanned = 0;
    double scan_duration_ms = 0.0;
    
    uint64_t total_artifacts_discovered = 0;
    
    // Status breakdown counts
    uint64_t count_successful = 0;
    uint64_t count_partial = 0;
    uint64_t count_corrupted = 0;
    uint64_t count_unvalidated = 0;
    uint64_t count_not_recoverable = 0;

    // Byte volume breakdown
    uint64_t bytes_successful = 0;
    uint64_t bytes_partial = 0;
    uint64_t bytes_corrupted = 0;
    uint64_t bytes_unvalidated = 0;

    // Confidence distribution buckets
    uint32_t confidence_very_high = 0; // 95-100%
    uint32_t confidence_high = 0;      // 80-94%
    uint32_t confidence_medium = 0;    // 60-79%
    uint32_t confidence_low = 0;       // 40-59%
    uint32_t confidence_very_low = 0;  // 0-39%
};

/**
 * @brief Certified sanitization event record for forensic audit.
 */
struct SanitizationRecord {
    std::string target_path;
    std::string media_type;
    std::string method_standard; // e.g. "NIST SP 800-88 Rev 1 Clear", "DoD 5220.22-M"
    int passes_completed = 0;
    uint64_t bytes_sanitized = 0;
    std::string pre_wipe_sha256;
    std::string post_wipe_sha256;
    double measured_entropy = 0.0;
    double pattern_match_rate = 0.0;
    bool verified_compliant = false;
    std::string start_timestamp_iso;
    std::string end_timestamp_iso;
    uint64_t audit_entry_id = 0;
    std::vector<std::string> limitations_disclosed;
};

/**
 * @brief Complete forensic report aggregating all case, evidence, recovery, and audit data.
 */
struct ForensicReport {
    std::string application_name = "ForensiVault Desktop Forensic Platform";
    std::string application_version = "1.0.0 (Smart India Hackathon Edition)";
    std::string report_id;
    std::string report_timestamp_iso;
    std::string classification = "CONFIDENTIAL // LAW ENFORCEMENT & FORENSIC AUDIT";

    // Case Information
    core::CaseInfo case_info;

    // Evidence & Acquisition
    AcquisitionMetadata acquisition;

    // Evidence Immutability Guarantee
    bool evidence_unmodified = true;
    std::string evidence_pre_hash;
    std::string evidence_post_hash;
    std::string immutability_verification_status;

    // Configuration & Filesystem
    ScanConfiguration scan_config;
    FilesystemSummary filesystem;

    // Recovery Results
    std::vector<ReportItem> recovered_items;
    RecoveryStatistics statistics;

    // Sanitization History in Case
    std::vector<SanitizationRecord> sanitization_history;

    // Cryptographic Chain of Custody & Audit History
    std::vector<logging::AuditEntry> audit_trail;
    bool audit_chain_verified = true;
    size_t audit_entries_count = 0;
    std::string latest_blockchain_hash;
};

} // namespace reporting
} // namespace forensivault
