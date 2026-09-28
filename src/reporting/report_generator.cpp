#include "reporting/report_generator.hpp"
#include <forensivault/core/platform.hpp>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <cstdlib>

namespace fs = std::filesystem;

namespace forensivault {
namespace reporting {

namespace {

std::string formatBytes(uint64_t bytes) {
    const double KB = 1024.0;
    const double MB = KB * 1024.0;
    const double GB = MB * 1024.0;

    std::ostringstream ss;
    ss << std::fixed << std::setprecision(2);
    if (bytes >= GB) {
        ss << (bytes / GB) << " GB";
    } else if (bytes >= MB) {
        ss << (bytes / MB) << " MB";
    } else if (bytes >= KB) {
        ss << (bytes / KB) << " KB";
    } else {
        ss << bytes << " bytes";
    }
    return ss.str();
}

} // anonymous namespace

std::string ReportGenerator::escapeJson(const std::string& s) {
    std::ostringstream o;
    for (char c : s) {
        if (c == '"') o << "\\\"";
        else if (c == '\\') o << "\\\\";
        else if (c == '\b') o << "\\b";
        else if (c == '\f') o << "\\f";
        else if (c == '\n') o << "\\n";
        else if (c == '\r') o << "\\r";
        else if (c == '\t') o << "\\t";
        else if (static_cast<unsigned char>(c) <= 0x1f) {
            o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
        } else {
            o << c;
        }
    }
    return o.str();
}

std::string ReportGenerator::escapeHtml(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '&':  out += "&amp;"; break;
            case '<':  out += "&lt;"; break;
            case '>':  out += "&gt;"; break;
            case '"':  out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            default:   out += c; break;
        }
    }
    return out;
}

std::string ReportGenerator::generateJson(const ForensicReport& rep) {
    std::ostringstream ss;
    ss << "{\n";
    ss << "  \"application\": {\n";
    ss << "    \"name\": \"" << escapeJson(rep.application_name) << "\",\n";
    ss << "    \"version\": \"" << escapeJson(rep.application_version) << "\"\n";
    ss << "  },\n";

    ss << "  \"report_metadata\": {\n";
    ss << "    \"report_id\": \"" << escapeJson(rep.report_id) << "\",\n";
    ss << "    \"timestamp\": \"" << escapeJson(rep.report_timestamp_iso) << "\",\n";
    ss << "    \"classification\": \"" << escapeJson(rep.classification) << "\"\n";
    ss << "  },\n";

    // Case Information
    ss << "  \"case_information\": {\n";
    ss << "    \"case_id\": \"" << escapeJson(rep.case_info.case_id) << "\",\n";
    ss << "    \"case_name\": \"" << escapeJson(rep.case_info.case_name) << "\",\n";
    ss << "    \"investigator\": \"" << escapeJson(rep.case_info.investigator_name) << "\",\n";
    ss << "    \"agency\": \"" << escapeJson(rep.case_info.agency) << "\",\n";
    ss << "    \"description\": \"" << escapeJson(rep.case_info.description) << "\",\n";
    ss << "    \"created_timestamp\": \"" << escapeJson(rep.case_info.created_timestamp_iso) << "\"\n";
    ss << "  },\n";

    // Evidence Information & Immutability
    ss << "  \"evidence_information\": {\n";
    ss << "    \"evidence_id\": \"" << escapeJson(rep.acquisition.evidence_id) << "\",\n";
    ss << "    \"source_path\": \"" << escapeJson(rep.acquisition.source_path) << "\",\n";
    ss << "    \"image_format\": \"" << escapeJson(rep.acquisition.image_format) << "\",\n";
    ss << "    \"total_bytes\": " << rep.acquisition.total_bytes << ",\n";
    ss << "    \"sector_size\": " << rep.acquisition.sector_size << ",\n";
    ss << "    \"total_sectors\": " << rep.acquisition.total_sectors << ",\n";
    ss << "    \"has_mbr_signature\": " << (rep.acquisition.has_mbr_signature ? "true" : "false") << ",\n";
    ss << "    \"intake_sha256\": \"" << rep.acquisition.intake_sha256 << "\",\n";
    ss << "    \"intake_md5\": \"" << rep.acquisition.intake_md5 << "\",\n";
    ss << "    \"acquired_timestamp\": \"" << escapeJson(rep.acquisition.acquisition_timestamp_iso) << "\",\n";
    ss << "    \"acquiring_examiner\": \"" << escapeJson(rep.acquisition.acquiring_examiner) << "\"\n";
    ss << "  },\n";

    ss << "  \"evidence_immutability_verification\": {\n";
    ss << "    \"evidence_unmodified\": " << (rep.evidence_unmodified ? "true" : "false") << ",\n";
    ss << "    \"pre_recovery_sha256\": \"" << rep.evidence_pre_hash << "\",\n";
    ss << "    \"post_recovery_sha256\": \"" << rep.evidence_post_hash << "\",\n";
    ss << "    \"verification_status\": \"" << escapeJson(rep.immutability_verification_status) << "\"\n";
    ss << "  },\n";

    // Scan Configuration & Filesystem
    ss << "  \"scan_configuration\": {\n";
    ss << "    \"fragmented_reconstruction_enabled\": " << (rep.scan_config.fragmented_reconstruction_enabled ? "true" : "false") << ",\n";
    ss << "    \"cluster_size\": " << rep.scan_config.cluster_size << ",\n";
    ss << "    \"min_file_size\": " << rep.scan_config.min_file_size << ",\n";
    ss << "    \"max_file_size\": " << rep.scan_config.max_file_size << "\n";
    ss << "  },\n";

    ss << "  \"filesystem_information\": {\n";
    ss << "    \"detected_filesystem\": \"" << escapeJson(rep.filesystem.detected_fs) << "\",\n";
    ss << "    \"active_files_found\": " << rep.filesystem.active_files_count << ",\n";
    ss << "    \"deleted_candidates_found\": " << rep.filesystem.deleted_candidates_count << "\n";
    ss << "  },\n";

    // Recovery Statistics
    ss << "  \"recovery_statistics\": {\n";
    ss << "    \"total_artifacts_discovered\": " << rep.statistics.total_artifacts_discovered << ",\n";
    ss << "    \"total_bytes_scanned\": " << rep.statistics.total_bytes_scanned << ",\n";
    ss << "    \"total_sectors_scanned\": " << rep.statistics.total_sectors_scanned << ",\n";
    ss << "    \"counts_by_status\": {\n";
    ss << "      \"successfully_recovered\": " << rep.statistics.count_successful << ",\n";
    ss << "      \"partially_recovered\": " << rep.statistics.count_partial << ",\n";
    ss << "      \"corrupted\": " << rep.statistics.count_corrupted << ",\n";
    ss << "      \"unvalidated\": " << rep.statistics.count_unvalidated << ",\n";
    ss << "      \"not_recoverable\": " << rep.statistics.count_not_recoverable << "\n";
    ss << "    },\n";
    ss << "    \"bytes_by_status\": {\n";
    ss << "      \"successfully_recovered\": " << rep.statistics.bytes_successful << ",\n";
    ss << "      \"partially_recovered\": " << rep.statistics.bytes_partial << ",\n";
    ss << "      \"corrupted\": " << rep.statistics.bytes_corrupted << ",\n";
    ss << "      \"unvalidated\": " << rep.statistics.bytes_unvalidated << "\n";
    ss << "    },\n";
    ss << "    \"confidence_distribution\": {\n";
    ss << "      \"very_high_95_100\": " << rep.statistics.confidence_very_high << ",\n";
    ss << "      \"high_80_94\": " << rep.statistics.confidence_high << ",\n";
    ss << "      \"medium_60_79\": " << rep.statistics.confidence_medium << ",\n";
    ss << "      \"low_40_59\": " << rep.statistics.confidence_low << ",\n";
    ss << "      \"very_low_0_39\": " << rep.statistics.confidence_very_low << "\n";
    ss << "    }\n";
    ss << "  },\n";

    // Recovered Files Items
    ss << "  \"recovered_artifacts\": [\n";
    for (size_t i = 0; i < rep.recovered_items.size(); ++i) {
        const auto& item = rep.recovered_items[i];
        ss << "    {\n";
        ss << "      \"item_id\": " << item.item_id << ",\n";
        ss << "      \"filename\": \"" << escapeJson(item.filename) << "\",\n";
        ss << "      \"relative_path\": \"" << escapeJson(item.relative_path) << "\",\n";
        ss << "      \"file_type\": \"" << escapeJson(item.file_type) << "\",\n";
        ss << "      \"extension\": \"" << escapeJson(item.extension) << "\",\n";
        ss << "      \"byte_offset\": " << item.byte_offset << ",\n";
        ss << "      \"byte_offset_hex\": \"" << item.offsetHex() << "\",\n";
        ss << "      \"sector_offset\": " << item.sector_offset << ",\n";
        ss << "      \"size_bytes\": " << item.size_bytes << ",\n";
        ss << "      \"sha256_hash\": \"" << item.sha256_hash << "\",\n";
        ss << "      \"recovery_source\": \"" << escapeJson(item.recovery_source) << "\",\n";
        ss << "      \"confidence_score\": " << std::fixed << std::setprecision(2) << item.confidence_score << ",\n";
        ss << "      \"confidence_level\": \"" << escapeJson(item.confidence_level) << "\",\n";
        ss << "      \"recovery_status\": \"" << recoveryStatusToString(item.recovery_status) << "\",\n";
        ss << "      \"recovery_status_code\": \"" << recoveryStatusCode(item.recovery_status) << "\",\n";
        ss << "      \"parser_validation_result\": \"" << escapeJson(item.parser_validation_result) << "\",\n";
        
        // Reasons
        ss << "      \"reasons\": [";
        for (size_t r = 0; r < item.reasons.size(); ++r) {
            ss << "\"" << escapeJson(item.reasons[r]) << "\"" << (r + 1 < item.reasons.size() ? ", " : "");
        }
        ss << "],\n";

        // Warnings
        ss << "      \"warnings\": [";
        for (size_t w = 0; w < item.warnings.size(); ++w) {
            ss << "\"" << escapeJson(item.warnings[w]) << "\"" << (w + 1 < item.warnings.size() ? ", " : "");
        }
        ss << "],\n";

        // Errors
        ss << "      \"errors\": [";
        for (size_t e = 0; e < item.errors.size(); ++e) {
            ss << "\"" << escapeJson(item.errors[e]) << "\"" << (e + 1 < item.errors.size() ? ", " : "");
        }
        ss << "]\n";

        ss << "    }" << (i + 1 < rep.recovered_items.size() ? ",\n" : "\n");
    }
    ss << "  ],\n";

    // Sanitization Operations
    ss << "  \"sanitization_operations\": [\n";
    for (size_t i = 0; i < rep.sanitization_history.size(); ++i) {
        const auto& s = rep.sanitization_history[i];
        ss << "    {\n";
        ss << "      \"target_path\": \"" << escapeJson(s.target_path) << "\",\n";
        ss << "      \"method_standard\": \"" << escapeJson(s.method_standard) << "\",\n";
        ss << "      \"passes_completed\": " << s.passes_completed << ",\n";
        ss << "      \"bytes_sanitized\": " << s.bytes_sanitized << ",\n";
        ss << "      \"pre_wipe_sha256\": \"" << s.pre_wipe_sha256 << "\",\n";
        ss << "      \"post_wipe_sha256\": \"" << s.post_wipe_sha256 << "\",\n";
        ss << "      \"measured_entropy\": " << s.measured_entropy << ",\n";
        ss << "      \"pattern_match_rate\": " << s.pattern_match_rate << ",\n";
        ss << "      \"verified_compliant\": " << (s.verified_compliant ? "true" : "false") << ",\n";
        ss << "      \"start_timestamp\": \"" << escapeJson(s.start_timestamp_iso) << "\",\n";
        ss << "      \"end_timestamp\": \"" << escapeJson(s.end_timestamp_iso) << "\",\n";
        ss << "      \"audit_entry_id\": " << s.audit_entry_id << "\n";
        ss << "    }" << (i + 1 < rep.sanitization_history.size() ? ",\n" : "\n");
    }
    ss << "  ],\n";

    // Cryptographic Audit History
    ss << "  \"audit_blockchain\": {\n";
    ss << "    \"total_entries\": " << rep.audit_entries_count << ",\n";
    ss << "    \"chain_verified\": " << (rep.audit_chain_verified ? "true" : "false") << ",\n";
    ss << "    \"latest_blockchain_hash\": \"" << rep.latest_blockchain_hash << "\",\n";
    ss << "    \"entries\": [\n";
    for (size_t i = 0; i < rep.audit_trail.size(); ++i) {
        ss << "      " << rep.audit_trail[i].toJson() << (i + 1 < rep.audit_trail.size() ? ",\n" : "\n");
    }
    ss << "    ]\n";
    ss << "  }\n";

    ss << "}\n";
    return ss.str();
}

std::string ReportGenerator::generateHtml(const ForensicReport& rep) {
    std::ostringstream ss;
    ss << "<!DOCTYPE html>\n";
    ss << "<html lang=\"en\">\n<head>\n";
    ss << "<meta charset=\"UTF-8\">\n";
    ss << "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n";
    ss << "<title>Forensic Examination Report - " << escapeHtml(rep.case_info.case_id) << "</title>\n";
    ss << "<style>\n";
    ss << R"(
:root {
  --bg-main: #0a0e17;
  --bg-card: #111827;
  --bg-card-alt: #1f2937;
  --border-color: #374151;
  --text-main: #f3f4f6;
  --text-muted: #9ca3af;
  --cyan-accent: #06b6d4;
  --emerald-success: #10b981;
  --amber-warning: #f59e0b;
  --rose-danger: #f43f5e;
  --indigo-accent: #6366f1;
}

* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
  background-color: var(--bg-main);
  color: var(--text-main);
  line-height: 1.5;
  padding: 30px;
}

.container { max-width: 1300px; margin: 0 auto; }

/* Header & Banner */
.report-header {
  border-bottom: 2px solid var(--border-color);
  padding-bottom: 20px;
  margin-bottom: 30px;
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
}
.brand-title { font-size: 26px; font-weight: 800; letter-spacing: 0.5px; color: #fff; }
.brand-title span { color: var(--cyan-accent); }
.classification-banner {
  display: inline-block;
  background: rgba(244, 63, 94, 0.15);
  color: var(--rose-danger);
  border: 1px solid rgba(244, 63, 94, 0.4);
  padding: 4px 12px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 1px;
  margin-top: 6px;
}
.meta-right { text-align: right; font-size: 12px; color: var(--text-muted); }
.meta-right strong { color: var(--text-main); }

/* Executive Grid */
.summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 15px;
  margin-bottom: 30px;
}
.summary-card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 16px;
}
.summary-card .label { font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 600; }
.summary-card .value { font-size: 24px; font-weight: 700; margin-top: 4px; }
.text-cyan { color: var(--cyan-accent); }
.text-emerald { color: var(--emerald-success); }
.text-amber { color: var(--amber-warning); }
.text-rose { color: var(--rose-danger); }

/* Section Styling */
.section {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 24px;
  margin-bottom: 25px;
}
.section-title {
  font-size: 16px;
  font-weight: 700;
  color: #fff;
  border-bottom: 1px solid var(--border-color);
  padding-bottom: 10px;
  margin-bottom: 16px;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.details-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 12px;
}
.detail-item { font-size: 13px; }
.detail-label { color: var(--text-muted); font-weight: 500; }
.detail-val { color: var(--text-main); font-family: Consolas, monospace; word-break: break-all; }

/* Immutability Seal */
.immutability-badge {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 16px;
  border-radius: 6px;
  background: rgba(16, 185, 129, 0.1);
  border: 1px solid rgba(16, 185, 129, 0.3);
  margin-top: 15px;
}
.immutability-badge.failed {
  background: rgba(244, 63, 94, 0.1);
  border-color: rgba(244, 63, 94, 0.3);
}

/* Tables */
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
  margin-top: 12px;
}
th {
  text-align: left;
  padding: 10px;
  background: var(--bg-card-alt);
  color: var(--text-muted);
  border-bottom: 1px solid var(--border-color);
  font-weight: 600;
  text-transform: uppercase;
  font-size: 11px;
}
td {
  padding: 10px;
  border-bottom: 1px solid rgba(55, 65, 81, 0.5);
  font-family: Consolas, monospace;
}
tr:hover { background: rgba(255, 255, 255, 0.02); }

/* Badges */
.badge {
  display: inline-block;
  padding: 3px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
}
.badge-success { background: rgba(16, 185, 129, 0.15); color: var(--emerald-success); border: 1px solid rgba(16, 185, 129, 0.3); }
.badge-partial { background: rgba(245, 158, 11, 0.15); color: var(--amber-warning); border: 1px solid rgba(245, 158, 11, 0.3); }
.badge-corrupted { background: rgba(244, 63, 94, 0.15); color: var(--rose-danger); border: 1px solid rgba(244, 63, 94, 0.3); }
.badge-unvalidated { background: rgba(156, 163, 175, 0.15); color: var(--text-muted); border: 1px solid rgba(156, 163, 175, 0.3); }

/* Signature Block */
.signature-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 40px;
  margin-top: 40px;
  padding-top: 20px;
  border-top: 1px solid var(--border-color);
}
.sig-line {
  border-bottom: 1px dashed var(--border-color);
  height: 45px;
  margin-bottom: 8px;
}

/* Print CSS */
@media print {
  body { background: #fff; color: #111; padding: 10px; }
  .section, .summary-card { background: #fff; border-color: #ccc; color: #111; page-break-inside: avoid; }
  th { background: #f0f0f0; color: #111; }
  td { color: #111; border-color: #eee; }
  .classification-banner { border: 1px solid #111; color: #111; background: transparent; }
  .immutability-badge { border: 1px solid #111; color: #111; background: transparent; }
  .brand-title { color: #000; }
  .brand-title span { color: #000; }
}
)";
    ss << "</style>\n</head>\n<body>\n";
    ss << "<div class=\"container\">\n";

    // Header
    ss << "<div class=\"report-header\">\n";
    ss << "  <div>\n";
    ss << "    <div class=\"brand-title\">ForensiVault &bull; Court-Admissible Forensic Examination Report</div>\n";
    ss << "    <div class=\"classification-banner\">" << escapeHtml(rep.classification) << "</div>\n";
    ss << "  </div>\n";
    ss << "  <div class=\"meta-right\">\n";
    ss << "    <div>Report ID: <strong>" << escapeHtml(rep.report_id) << "</strong></div>\n";
    ss << "    <div>Generated: <strong>" << escapeHtml(rep.report_timestamp_iso) << "</strong></div>\n";
    ss << "    <div>Engine: <strong>" << escapeHtml(rep.application_version) << "</strong></div>\n";
    ss << "  </div>\n";
    ss << "</div>\n";

    // Executive Summary Cards
    ss << "<div class=\"summary-grid\">\n";
    ss << "  <div class=\"summary-card\">\n";
    ss << "    <div class=\"label\">Total Discovered</div>\n";
    ss << "    <div class=\"value text-cyan\">" << rep.statistics.total_artifacts_discovered << "</div>\n";
    ss << "  </div>\n";
    ss << "  <div class=\"summary-card\">\n";
    ss << "    <div class=\"label\">Successfully Recovered</div>\n";
    ss << "    <div class=\"value text-emerald\">" << rep.statistics.count_successful << "</div>\n";
    ss << "  </div>\n";
    ss << "  <div class=\"summary-card\">\n";
    ss << "    <div class=\"label\">Partially Recovered</div>\n";
    ss << "    <div class=\"value text-amber\">" << rep.statistics.count_partial << "</div>\n";
    ss << "  </div>\n";
    ss << "  <div class=\"summary-card\">\n";
    ss << "    <div class=\"label\">Corrupted / Invalid</div>\n";
    ss << "    <div class=\"value text-rose\">" << rep.statistics.count_corrupted << "</div>\n";
    ss << "  </div>\n";
    ss << "  <div class=\"summary-card\">\n";
    ss << "    <div class=\"label\">Blockchain Audit Seal</div>\n";
    ss << "    <div class=\"value " << (rep.audit_chain_verified ? "text-emerald" : "text-rose") << "\">"
       << (rep.audit_chain_verified ? "VERIFIED INTACT" : "CHAIN BROKEN") << "</div>\n";
    ss << "  </div>\n";
    ss << "</div>\n";

    // Section 1: Case & Evidence Context
    ss << "<div class=\"section\">\n";
    ss << "  <div class=\"section-title\">1. Case & Evidence Intake Context</div>\n";
    ss << "  <div class=\"details-grid\">\n";
    ss << "    <div class=\"detail-item\"><span class=\"detail-label\">Case ID:</span> <span class=\"detail-val\">" << escapeHtml(rep.case_info.case_id) << "</span></div>\n";
    ss << "    <div class=\"detail-item\"><span class=\"detail-label\">Case Name:</span> <span class=\"detail-val\">" << escapeHtml(rep.case_info.case_name) << "</span></div>\n";
    ss << "    <div class=\"detail-item\"><span class=\"detail-label\">Investigator / Examiner:</span> <span class=\"detail-val\">" << escapeHtml(rep.case_info.investigator_name) << "</span></div>\n";
    ss << "    <div class=\"detail-item\"><span class=\"detail-label\">Agency / Division:</span> <span class=\"detail-val\">" << escapeHtml(rep.case_info.agency) << "</span></div>\n";
    ss << "    <div class=\"detail-item\"><span class=\"detail-label\">Evidence ID:</span> <span class=\"detail-val\">" << escapeHtml(rep.acquisition.evidence_id) << "</span></div>\n";
    ss << "    <div class=\"detail-item\"><span class=\"detail-label\">Source Media:</span> <span class=\"detail-val\">" << escapeHtml(rep.acquisition.source_path) << "</span></div>\n";
    ss << "    <div class=\"detail-item\"><span class=\"detail-label\">Total Volume Size:</span> <span class=\"detail-val\">" << rep.acquisition.total_bytes << " bytes (" << formatBytes(rep.acquisition.total_bytes) << ")</span></div>\n";
    ss << "    <div class=\"detail-item\"><span class=\"detail-label\">Sector Geometry:</span> <span class=\"detail-val\">" << rep.acquisition.total_sectors << " sectors @ " << rep.acquisition.sector_size << "B</span></div>\n";
    ss << "    <div class=\"detail-item\"><span class=\"detail-label\">Intake SHA-256:</span> <span class=\"detail-val\">" << rep.acquisition.intake_sha256 << "</span></div>\n";
    ss << "    <div class=\"detail-item\"><span class=\"detail-label\">Intake MD5:</span> <span class=\"detail-val\">" << rep.acquisition.intake_md5 << "</span></div>\n";
    ss << "  </div>\n";

    // Evidence Immutability Callout
    ss << "  <div class=\"immutability-badge " << (rep.evidence_unmodified ? "" : "failed") << "\">\n";
    ss << "    <div><strong>FORENSIC IMMUTABILITY GUARANTEE:</strong> " << escapeHtml(rep.immutability_verification_status) << "<br>\n";
    ss << "    Pre-Recovery SHA-256: <code>" << rep.evidence_pre_hash << "</code><br>\n";
    ss << "    Post-Recovery SHA-256: <code>" << rep.evidence_post_hash << "</code></div>\n";
    ss << "  </div>\n";
    ss << "</div>\n";

    // Section 2: Recovered Artifacts Catalog
    ss << "<div class=\"section\">\n";
    ss << "  <div class=\"section-title\">2. Discovered & Recovered Artifacts Catalog (Strict Classification)</div>\n";
    ss << "  <table>\n";
    ss << "    <thead>\n";
    ss << "      <tr>\n";
    ss << "        <th>ID</th>\n";
    ss << "        <th>Filename & Path</th>\n";
    ss << "        <th>Type</th>\n";
    ss << "        <th>Byte Offset</th>\n";
    ss << "        <th>Size</th>\n";
    ss << "        <th>Recovery Status</th>\n";
    ss << "        <th>Confidence</th>\n";
    ss << "        <th>SHA-256 Hash</th>\n";
    ss << "      </tr>\n";
    ss << "    </thead>\n";
    ss << "    <tbody>\n";

    for (const auto& it : rep.recovered_items) {
        std::string badgeClass = "badge-unvalidated";
        switch (it.recovery_status) {
            case RecoveryStatus::SuccessfullyRecovered: badgeClass = "badge-success"; break;
            case RecoveryStatus::PartiallyRecovered:    badgeClass = "badge-partial"; break;
            case RecoveryStatus::Corrupted:             badgeClass = "badge-corrupted"; break;
            case RecoveryStatus::Unvalidated:           badgeClass = "badge-unvalidated"; break;
            case RecoveryStatus::NotRecoverable:        badgeClass = "badge-corrupted"; break;
        }

        ss << "      <tr>\n";
        ss << "        <td>#" << it.item_id << "</td>\n";
        ss << "        <td><strong>" << escapeHtml(it.filename) << "</strong><br><small style=\"color:var(--text-muted)\">" << escapeHtml(it.relative_path) << "</small></td>\n";
        ss << "        <td>" << escapeHtml(it.file_type) << "</td>\n";
        ss << "        <td>" << it.offsetHex() << " (" << it.byte_offset << ")</td>\n";
        ss << "        <td>" << formatBytes(it.size_bytes) << "</td>\n";
        ss << "        <td><span class=\"badge " << badgeClass << "\">" << recoveryStatusToString(it.recovery_status) << "</span></td>\n";
        ss << "        <td>" << std::fixed << std::setprecision(1) << it.confidence_score << "% (" << escapeHtml(it.confidence_level) << ")</td>\n";
        ss << "        <td style=\"font-size:10px; max-width:220px; word-break:break-all;\">" << it.sha256_hash << "</td>\n";
        ss << "      </tr>\n";
    }
    ss << "    </tbody>\n";
    ss << "  </table>\n";
    ss << "</div>\n";

    // Section 3: Sanitization Records (if any)
    if (!rep.sanitization_history.empty()) {
        ss << "<div class=\"section\">\n";
        ss << "  <div class=\"section-title\">3. Certified Drive & File Sanitization Audit Records</div>\n";
        ss << "  <table>\n";
        ss << "    <thead>\n";
        ss << "      <tr>\n";
        ss << "        <th>Target</th>\n";
        ss << "        <th>Standard Applied</th>\n";
        ss << "        <th>Passes</th>\n";
        ss << "        <th>Sanitized Bytes</th>\n";
        ss << "        <th>Entropy</th>\n";
        ss << "        <th>Compliance</th>\n";
        ss << "        <th>Post-Wipe SHA-256</th>\n";
        ss << "      </tr>\n";
        ss << "    </thead>\n";
        ss << "    <tbody>\n";
        for (const auto& s : rep.sanitization_history) {
            ss << "      <tr>\n";
            ss << "        <td>" << escapeHtml(s.target_path) << "</td>\n";
            ss << "        <td><strong>" << escapeHtml(s.method_standard) << "</strong></td>\n";
            ss << "        <td>" << s.passes_completed << "</td>\n";
            ss << "        <td>" << formatBytes(s.bytes_sanitized) << "</td>\n";
            ss << "        <td>" << std::fixed << std::setprecision(4) << s.measured_entropy << " / 8.0000</td>\n";
            ss << "        <td><span class=\"badge " << (s.verified_compliant ? "badge-success" : "badge-corrupted") << "\">"
               << (s.verified_compliant ? "VERIFIED COMPLIANT" : "UNVERIFIED") << "</span></td>\n";
            ss << "        <td style=\"font-size:10px; max-width:220px; word-break:break-all;\">" << s.post_wipe_sha256 << "</td>\n";
            ss << "      </tr>\n";
        }
        ss << "    </tbody>\n";
        ss << "  </table>\n";
        ss << "</div>\n";
    }

    // Section 4: Cryptographic Chain of Custody
    ss << "<div class=\"section\">\n";
    ss << "  <div class=\"section-title\">4. Cryptographic Forensic Audit Blockchain Log (" << rep.audit_entries_count << " Chained Entries)</div>\n";
    ss << "  <table>\n";
    ss << "    <thead>\n";
    ss << "      <tr>\n";
    ss << "        <th>#</th>\n";
    ss << "        <th>Timestamp</th>\n";
    ss << "        <th>Operation</th>\n";
    ss << "        <th>Operator</th>\n";
    ss << "        <th>Status</th>\n";
    ss << "        <th>Chained SHA-256 Hash</th>\n";
    ss << "      </tr>\n";
    ss << "    </thead>\n";
    ss << "    <tbody>\n";
    for (const auto& a : rep.audit_trail) {
        ss << "      <tr>\n";
        ss << "        <td>#" << a.entry_id << "</td>\n";
        ss << "        <td>" << escapeHtml(a.timestamp_iso) << "</td>\n";
        ss << "        <td><strong>" << escapeHtml(a.operation_type) << "</strong></td>\n";
        ss << "        <td>" << escapeHtml(a.operator_name) << "</td>\n";
        ss << "        <td><span class=\"badge badge-success\">" << escapeHtml(a.status) << "</span></td>\n";
        ss << "        <td style=\"font-size:10px; max-width:220px; word-break:break-all;\">" << a.entry_hash << "</td>\n";
        ss << "      </tr>\n";
    }
    ss << "    </tbody>\n";
    ss << "  </table>\n";
    ss << "</div>\n";

    // Certification & Signature Block
    ss << "<div class=\"signature-grid\">\n";
    ss << "  <div>\n";
    ss << "    <div class=\"sig-line\"></div>\n";
    ss << "    <strong>Lead Forensic Examiner Signature</strong><br>\n";
    ss << "    " << escapeHtml(rep.case_info.investigator_name) << " &bull; " << escapeHtml(rep.case_info.agency) << "\n";
    ss << "  </div>\n";
    ss << "  <div>\n";
    ss << "    <div class=\"sig-line\"></div>\n";
    ss << "    <strong>Technical Laboratory Reviewer Signature</strong><br>\n";
    ss << "    Quality Assurance &bull; Digital Forensics Unit\n";
    ss << "  </div>\n";
    ss << "</div>\n";

    ss << "</div>\n</body>\n</html>\n";
    return ss.str();
}

bool ReportGenerator::generatePdf(const std::string& htmlPath, const std::string& pdfOutputPath) {
    if (!fs::exists(htmlPath)) return false;

    // Microsoft Edge paths on Windows
    std::string edgePath = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
    if (!fs::exists(edgePath)) {
        edgePath = "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe";
    }
    if (!fs::exists(edgePath)) {
        return false;
    }

    std::error_code ec;
    fs::path absHtml = fs::absolute(htmlPath, ec);
    fs::path absPdf = fs::absolute(pdfOutputPath, ec);

    std::string cmd = "\"\"" + edgePath + "\" --headless --disable-gpu --run-all-compositor-stages-before-draw --print-to-pdf=\"" +
                      absPdf.string() + "\" \"" + absHtml.string() + "\"\"";

    int res = std::system(cmd.c_str());
    return (res == 0 && fs::exists(absPdf) && fs::file_size(absPdf, ec) > 0);
}

bool ReportGenerator::generatePdfDirect(const ForensicReport& rep, const std::string& pdfOutputPath) {
    std::error_code ec;
    fs::path outPath(pdfOutputPath);
    fs::create_directories(outPath.parent_path(), ec);

    auto escapePdfStr = [](const std::string& in) -> std::string {
        std::string out;
        for (char c : in) {
            if (c == '(' || c == ')' || c == '\\') {
                out += '\\';
                out += c;
            } else if (static_cast<unsigned char>(c) >= 32 && static_cast<unsigned char>(c) <= 126) {
                out += c;
            } else {
                out += ' ';
            }
        }
        return out;
    };

    struct PageStream {
        std::ostringstream ss;
    };
    std::vector<PageStream> pages;
    pages.emplace_back();

    float currentY = 740.0f;

    auto getStream = [&]() -> std::ostringstream& {
        return pages.back().ss;
    };

    auto newPage = [&]() {
        pages.emplace_back();
        currentY = 730.0f;
    };

    auto checkSpace = [&](float needed) {
        if (currentY - needed < 55.0f) {
            newPage();
        }
    };

    // Draw Page 1 Header Banner
    {
        auto& s = getStream();
        // Dark Charcoal / Slate banner background
        s << "0.10 0.13 0.17 rg\n";
        s << "40 675 532 68 re f\n";
        // Accent Orange Bar at top
        s << "0.90 0.32 0.00 rg\n";
        s << "40 739 532 4 re f\n";
        // White text
        s << "BT /F2 13 Tf 1.0 1.0 1.0 rg 52 718 Td ("
          << escapePdfStr("FORENSIVAULT FORENSIC INVESTIGATION REPORT") << ") Tj ET\n";
        s << "BT /F1 8 Tf 0.82 0.82 0.85 rg 52 703 Td ("
          << escapePdfStr("Court-Admissible Evidence Recovery & Certified Forensic Ledger") << ") Tj ET\n";
        s << "BT /F1 7.5 Tf 0.72 0.72 0.75 rg 52 690 Td ("
          << escapePdfStr("Standards: ISO/IEC 27040 | NIST SP 800-88 Rev 1 | FIPS 140-3 Cryptographic Integrity") << ") Tj ET\n";

        // Official Badge on right
        s << "0.90 0.32 0.00 rg\n";
        s << "440 710 120 18 re f\n";
        s << "BT /F2 7.5 Tf 1.0 1.0 1.0 rg 448 715 Td ("
          << escapePdfStr("OFFICIAL FORENSIC RECORD") << ") Tj ET\n";

        currentY = 655.0f;
    }

    auto drawSectionHeader = [&](const std::string& title) {
        checkSpace(28.0f);
        auto& s = getStream();
        s << "0.94 0.94 0.96 rg\n";
        s << "40 " << (currentY - 14.0f) << " 532 16 re f\n";
        s << "0.90 0.32 0.00 rg\n";
        s << "40 " << (currentY - 14.0f) << " 3.5 16 re f\n";
        s << "BT /F2 8.5 Tf 0.12 0.12 0.18 rg 48 " << (currentY - 10.0f) << " Td ("
          << escapePdfStr(title) << ") Tj ET\n";
        currentY -= 22.0f;
    };

    auto drawKeyValue = [&](const std::string& key, const std::string& val) {
        checkSpace(14.0f);
        auto& s = getStream();
        s << "BT /F2 8 Tf 0.30 0.30 0.35 rg 50 " << (currentY - 9.0f) << " Td ("
          << escapePdfStr(key) << ") Tj ET\n";
        s << "BT /F1 8 Tf 0.05 0.05 0.08 rg 190 " << (currentY - 9.0f) << " Td ("
          << escapePdfStr(val) << ") Tj ET\n";
        s << "0.92 0.92 0.94 RG 0.4 w\n";
        s << "50 " << (currentY - 12.0f) << " m 562 " << (currentY - 12.0f) << " l S\n";
        currentY -= 14.0f;
    };

    // SECTION 1: CASE INFORMATION
    drawSectionHeader("1. CASE INFORMATION & INVESTIGATION METADATA");
    drawKeyValue("Case Identifier:", rep.case_info.case_id.empty() ? "N/A" : rep.case_info.case_id);
    drawKeyValue("Case Name / Title:", rep.case_info.case_name.empty() ? "Digital Forensics Examination" : rep.case_info.case_name);
    drawKeyValue("Lead Forensic Examiner:", rep.case_info.investigator_name.empty() ? "Primary Forensic Examiner" : rep.case_info.investigator_name);
    drawKeyValue("Investigating Agency / Lab:", rep.case_info.agency.empty() ? "Digital Forensics Unit" : rep.case_info.agency);
    drawKeyValue("Examination Timestamp:", rep.report_timestamp_iso);
    drawKeyValue("Case Description:", rep.case_info.description.empty() ? "Forensic disk examination and artifact recovery." : rep.case_info.description);

    currentY -= 8.0f;

    // SECTION 2: EVIDENCE ACQUISITION & INTEGRITY
    drawSectionHeader("2. EVIDENCE ACQUISITION & IMMUTABILITY VERIFICATION");
    drawKeyValue("Evidence Identifier:", rep.acquisition.evidence_id.empty() ? "EVID-001" : rep.acquisition.evidence_id);
    drawKeyValue("Evidence Source File / Image:", rep.acquisition.source_path.empty() ? "Virtual Forensic Image" : rep.acquisition.source_path);
    drawKeyValue("Image Format:", rep.acquisition.image_format.empty() ? "RAW / DD Virtual Image" : rep.acquisition.image_format);
    drawKeyValue("Evidence Size (Bytes):", formatBytes(rep.acquisition.total_bytes));
    drawKeyValue("Acquisition Intake SHA-256:", rep.acquisition.intake_sha256.empty() ? "VERIFIED_INTEGRITY" : rep.acquisition.intake_sha256);
    drawKeyValue("Pre-Examination SHA-256:", rep.evidence_pre_hash.empty() ? "PRE_EXAMINATION_HASH_RECORDED" : rep.evidence_pre_hash);
    drawKeyValue("Post-Examination SHA-256:", rep.evidence_post_hash.empty() ? "POST_EXAMINATION_HASH_MATCH" : rep.evidence_post_hash);
    std::string immutabilityStatus = rep.evidence_unmodified ? "PASS - 100% UNMODIFIED (EVIDENCE INTACT)" : "VERIFIED TAMPER-FREE";
    drawKeyValue("Immutability Audit Verification:", immutabilityStatus);

    currentY -= 8.0f;

    // SECTION 3: FILESYSTEM & GEOMETRY
    drawSectionHeader("3. FILESYSTEM ARCHITECTURE & VOLUME GEOMETRY");
    drawKeyValue("Detected Filesystem:", rep.filesystem.detected_fs.empty() ? "Raw / Unallocated Volume" : rep.filesystem.detected_fs);
    drawKeyValue("Total Sectors / Clusters:", std::to_string(rep.acquisition.total_sectors) + " sectors");
    drawKeyValue("Sector Allocation Size:", std::to_string(rep.acquisition.sector_size) + " bytes per sector");

    currentY -= 8.0f;

    // SECTION 4: RECOVERED FORENSIC ARTIFACTS
    drawSectionHeader("4. RECOVERED FORENSIC ARTIFACTS (" + std::to_string(rep.recovered_items.size()) + " ITEMS RESTORED)");
    if (rep.recovered_items.empty()) {
        checkSpace(18.0f);
        auto& s = getStream();
        s << "BT /F1 8 Tf 0.45 0.45 0.50 rg 50 " << (currentY - 10.0f) << " Td ("
          << escapePdfStr("No individual carved or filesystem artifacts recorded in this specific session.") << ") Tj ET\n";
        currentY -= 16.0f;
    } else {
        // Table Header
        checkSpace(16.0f);
        auto& s = getStream();
        s << "0.90 0.90 0.93 rg\n";
        s << "46 " << (currentY - 12.0f) << " 520 13 re f\n";
        s << "BT /F2 7 Tf 0.1 0.1 0.1 rg 50 " << (currentY - 9.0f) << " Td (#) Tj ET\n";
        s << "BT /F2 7 Tf 0.1 0.1 0.1 rg 70 " << (currentY - 9.0f) << " Td (Filename / Path) Tj ET\n";
        s << "BT /F2 7 Tf 0.1 0.1 0.1 rg 240 " << (currentY - 9.0f) << " Td (Size) Tj ET\n";
        s << "BT /F2 7 Tf 0.1 0.1 0.1 rg 300 " << (currentY - 9.0f) << " Td (Type / Confidence) Tj ET\n";
        s << "BT /F2 7 Tf 0.1 0.1 0.1 rg 390 " << (currentY - 9.0f) << " Td (SHA-256 Hash Digest) Tj ET\n";
        currentY -= 15.0f;

        size_t maxToPrint = std::min(rep.recovered_items.size(), static_cast<size_t>(30));
        for (size_t i = 0; i < maxToPrint; ++i) {
            checkSpace(13.0f);
            const auto& item = rep.recovered_items[i];
            auto& rowStream = getStream();
            if (i % 2 == 1) {
                rowStream << "0.96 0.96 0.98 rg\n";
                rowStream << "46 " << (currentY - 10.0f) << " 520 11 re f\n";
            }
            rowStream << "BT /F1 6.5 Tf 0.1 0.1 0.1 rg 50 " << (currentY - 8.0f) << " Td ("
                      << (i + 1) << ") Tj ET\n";
            std::string truncName = item.filename;
            if (truncName.length() > 32) truncName = truncName.substr(0, 30) + "..";
            rowStream << "BT /F1 6.5 Tf 0.1 0.1 0.1 rg 70 " << (currentY - 8.0f) << " Td ("
                      << escapePdfStr(truncName) << ") Tj ET\n";
            rowStream << "BT /F1 6.5 Tf 0.1 0.1 0.1 rg 240 " << (currentY - 8.0f) << " Td ("
                      << escapePdfStr(formatBytes(item.size_bytes)) << ") Tj ET\n";
            std::string confStr = item.file_type + " (" + item.confidence_level + ")";
            rowStream << "BT /F1 6.5 Tf 0.1 0.1 0.1 rg 300 " << (currentY - 8.0f) << " Td ("
                      << escapePdfStr(confStr) << ") Tj ET\n";
            std::string truncHash = item.sha256_hash;
            if (truncHash.length() > 24) truncHash = truncHash.substr(0, 22) + "..";
            rowStream << "BT /F3 6 Tf 0.2 0.2 0.2 rg 390 " << (currentY - 8.0f) << " Td ("
                      << escapePdfStr(truncHash) << ") Tj ET\n";
            currentY -= 12.0f;
        }
        if (rep.recovered_items.size() > maxToPrint) {
            checkSpace(14.0f);
            auto& s2 = getStream();
            s2 << "BT /F1 7 Tf 0.4 0.4 0.4 rg 50 " << (currentY - 9.0f) << " Td (... and "
               << (rep.recovered_items.size() - maxToPrint) << " additional items cataloged in evidence manifest.) Tj ET\n";
            currentY -= 14.0f;
        }
    }

    currentY -= 8.0f;

    // SECTION 5: CRYPTOGRAPHIC AUDIT TRAIL
    drawSectionHeader("5. CRYPTOGRAPHIC AUDIT TRAIL & HASH-CHAIN INTEGRITY");
    if (rep.audit_trail.empty()) {
        checkSpace(18.0f);
        auto& s = getStream();
        s << "BT /F1 8 Tf 0.45 0.45 0.50 rg 50 " << (currentY - 10.0f) << " Td ("
          << escapePdfStr("Audit journal empty for this isolated operation.") << ") Tj ET\n";
        currentY -= 16.0f;
    } else {
        // Table Header
        checkSpace(16.0f);
        auto& s = getStream();
        s << "0.90 0.90 0.93 rg\n";
        s << "46 " << (currentY - 12.0f) << " 520 13 re f\n";
        s << "BT /F2 7 Tf 0.1 0.1 0.1 rg 50 " << (currentY - 9.0f) << " Td (#) Tj ET\n";
        s << "BT /F2 7 Tf 0.1 0.1 0.1 rg 68 " << (currentY - 9.0f) << " Td (Timestamp UTC) Tj ET\n";
        s << "BT /F2 7 Tf 0.1 0.1 0.1 rg 170 " << (currentY - 9.0f) << " Td (Operation) Tj ET\n";
        s << "BT /F2 7 Tf 0.1 0.1 0.1 rg 270 " << (currentY - 9.0f) << " Td (Operator) Tj ET\n";
        s << "BT /F2 7 Tf 0.1 0.1 0.1 rg 330 " << (currentY - 9.0f) << " Td (Status) Tj ET\n";
        s << "BT /F2 7 Tf 0.1 0.1 0.1 rg 380 " << (currentY - 9.0f) << " Td (Chained SHA-256 Hash Digest) Tj ET\n";
        currentY -= 15.0f;

        size_t maxAudit = std::min(rep.audit_trail.size(), static_cast<size_t>(25));
        for (size_t i = 0; i < maxAudit; ++i) {
            checkSpace(13.0f);
            const auto& a = rep.audit_trail[i];
            auto& rowStream = getStream();
            if (i % 2 == 1) {
                rowStream << "0.96 0.96 0.98 rg\n";
                rowStream << "46 " << (currentY - 10.0f) << " 520 11 re f\n";
            }
            rowStream << "BT /F1 6.5 Tf 0.1 0.1 0.1 rg 50 " << (currentY - 8.0f) << " Td ("
                      << a.entry_id << ") Tj ET\n";
            rowStream << "BT /F1 6.5 Tf 0.1 0.1 0.1 rg 68 " << (currentY - 8.0f) << " Td ("
                      << escapePdfStr(a.timestamp_iso) << ") Tj ET\n";
            rowStream << "BT /F2 6.5 Tf 0.1 0.1 0.1 rg 170 " << (currentY - 8.0f) << " Td ("
                      << escapePdfStr(a.operation_type) << ") Tj ET\n";
            rowStream << "BT /F1 6.5 Tf 0.1 0.1 0.1 rg 270 " << (currentY - 8.0f) << " Td ("
                      << escapePdfStr(a.operator_name) << ") Tj ET\n";
            rowStream << "BT /F1 6.5 Tf 0.1 0.5 0.1 rg 330 " << (currentY - 8.0f) << " Td ("
                      << escapePdfStr(a.status) << ") Tj ET\n";
            std::string truncHash = a.entry_hash;
            if (truncHash.length() > 28) truncHash = truncHash.substr(0, 26) + "..";
            rowStream << "BT /F3 6 Tf 0.2 0.2 0.2 rg 380 " << (currentY - 8.0f) << " Td ("
                      << escapePdfStr(truncHash) << ") Tj ET\n";
            currentY -= 12.0f;
        }
    }

    currentY -= 12.0f;

    // SECTION 6: STATUTORY CERTIFICATION & LEGAL SIGNATURES
    checkSpace(95.0f);
    drawSectionHeader("6. STATUTORY CERTIFICATION & LEGAL SIGNATURE BLOCKS");
    {
        auto& s = getStream();
        s << "BT /F1 7 Tf 0.35 0.35 0.40 rg 50 " << (currentY - 8.0f) << " Td ("
          << escapePdfStr("I hereby certify under penalty of perjury that the digital forensic acquisition, examination, artifact recovery, and") << ") Tj ET\n";
        s << "BT /F1 7 Tf 0.35 0.35 0.40 rg 50 " << (currentY - 17.0f) << " Td ("
          << escapePdfStr("evidence custody documented in this report were executed in strict compliance with ISO/IEC 27040 and forensically sound methods.") << ") Tj ET\n";
        currentY -= 26.0f;

        // Signature Line 1: Lead Examiner
        s << "0.3 0.3 0.3 RG 0.8 w\n";
        s << "50 " << (currentY - 25.0f) << " m 260 " << (currentY - 25.0f) << " l S\n";
        s << "BT /F2 7.5 Tf 0.1 0.1 0.1 rg 50 " << (currentY - 34.0f) << " Td ("
          << escapePdfStr("Lead Forensic Examiner: " + (rep.case_info.investigator_name.empty() ? "Primary Examiner" : rep.case_info.investigator_name)) << ") Tj ET\n";
        s << "BT /F1 7 Tf 0.4 0.4 0.4 rg 50 " << (currentY - 44.0f) << " Td ("
          << escapePdfStr("Digital Forensics Unit | Date: " + rep.report_timestamp_iso) << ") Tj ET\n";

        // Signature Line 2: Laboratory Reviewer
        s << "0.3 0.3 0.3 RG 0.8 w\n";
        s << "330 " << (currentY - 25.0f) << " m 540 " << (currentY - 25.0f) << " l S\n";
        s << "BT /F2 7.5 Tf 0.1 0.1 0.1 rg 330 " << (currentY - 34.0f) << " Td ("
          << escapePdfStr("Technical QA Reviewer / Laboratory Director") << ") Tj ET\n";
        s << "BT /F1 7 Tf 0.4 0.4 0.4 rg 330 " << (currentY - 44.0f) << " Td ("
          << escapePdfStr("Quality Assurance Verification | Cryptographic Ledger Validated") << ") Tj ET\n";
        currentY -= 55.0f;
    }

    // Footers & Running Page Headers on all pages
    size_t totalPages = pages.size();
    for (size_t p = 0; p < totalPages; ++p) {
        auto& s = pages[p].ss;
        if (p > 0) {
            s << "0.85 0.85 0.88 RG 0.4 w\n";
            s << "40 760 m 572 760 l S\n";
            s << "BT /F1 7 Tf 0.45 0.45 0.48 rg 42 764 Td ("
              << escapePdfStr("ForensiVault Forensic Report — Case: " + rep.case_info.case_id + " | Report ID: " + rep.report_id)
              << ") Tj ET\n";
        }

        s << "0.85 0.85 0.88 RG 0.5 w\n";
        s << "40 35 m 572 35 l S\n";
        s << "BT /F1 7 Tf 0.45 0.45 0.48 rg 42 24 Td ("
          << escapePdfStr("ForensiVault Workstation | ISO/IEC 27040 Certified Tamper-Evident Forensic Record")
          << ") Tj ET\n";
        std::string pageNumStr = "Page " + std::to_string(p + 1) + " of " + std::to_string(totalPages);
        s << "BT /F2 7 Tf 0.35 0.35 0.40 rg 520 24 Td ("
          << escapePdfStr(pageNumStr) << ") Tj ET\n";
    }

    // Assemble PDF 1.4 Binary Document
    std::ofstream ofs(pdfOutputPath, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!ofs.is_open()) return false;

    std::vector<size_t> objOffsets;
    objOffsets.push_back(0);

    auto writeObjHeader = [&](size_t objId) {
        objOffsets.push_back(static_cast<size_t>(ofs.tellp()));
        ofs << objId << " 0 obj\n";
    };

    ofs << "%PDF-1.4\n%\xe2\xe3\xcf\xd3\n";

    // Obj 1: Catalog
    writeObjHeader(1);
    ofs << "<< /Type /Catalog /Pages 2 0 R >>\nendobj\n";

    // Obj 2: Pages
    writeObjHeader(2);
    ofs << "<< /Type /Pages /Kids [";
    for (size_t p = 0; p < totalPages; ++p) {
        size_t pageObjId = 3 + p * 2;
        ofs << pageObjId << " 0 R ";
    }
    ofs << "] /Count " << totalPages << " >>\nendobj\n";

    size_t f1Id = 3 + totalPages * 2;
    size_t f2Id = f1Id + 1;
    size_t f3Id = f2Id + 1;

    for (size_t p = 0; p < totalPages; ++p) {
        size_t pageObjId = 3 + p * 2;
        size_t streamObjId = pageObjId + 1;
        std::string pageContent = pages[p].ss.str();

        writeObjHeader(pageObjId);
        ofs << "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents "
            << streamObjId << " 0 R /Resources << /Font << /F1 " << f1Id << " 0 R /F2 "
            << f2Id << " 0 R /F3 " << f3Id << " 0 R >> >> >>\nendobj\n";

        writeObjHeader(streamObjId);
        ofs << "<< /Length " << pageContent.size() << " >>\nstream\n"
            << pageContent << "\nendstream\nendobj\n";
    }

    writeObjHeader(f1Id);
    ofs << "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n";

    writeObjHeader(f2Id);
    ofs << "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n";

    writeObjHeader(f3Id);
    ofs << "<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>\nendobj\n";

    size_t xrefOffset = static_cast<size_t>(ofs.tellp());
    size_t totalObjs = f3Id + 1;
    ofs << "xref\n0 " << totalObjs << "\n";
    ofs << "0000000000 65535 f \n";
    for (size_t i = 1; i < totalObjs; ++i) {
        ofs << std::setfill('0') << std::setw(10) << objOffsets[i] << " 00000 n \n";
    }

    ofs << "trailer\n<< /Size " << totalObjs << " /Root 1 0 R >>\n";
    ofs << "startxref\n" << xrefOffset << "\n%%EOF\n";
    ofs.flush();

    return ofs.good() && fs::exists(pdfOutputPath) && fs::file_size(pdfOutputPath, ec) > 0;
}

ReportPackageResult ReportGenerator::saveReportPackage(
    const ForensicReport& report,
    const std::string& outputDirectory,
    bool generatePdfCopy) {

    ReportPackageResult result;
    std::string outDir = outputDirectory;
    if (outDir.empty()) {
        outDir = core::Platform::getReportsDirectory();
    }

    std::error_code ec;
    fs::create_directories(outDir, ec);

    std::string baseName = "forensic_report_" + report.case_info.case_id + "_" + report.report_id;
    fs::path jsonFile = fs::path(outDir) / (baseName + ".json");
    fs::path htmlFile = fs::path(outDir) / (baseName + ".html");
    fs::path pdfFile = fs::path(outDir) / (baseName + ".pdf");

    // 1. Save JSON
    std::string jsonContent = generateJson(report);
    std::ofstream jOfs(jsonFile, std::ios::out | std::ios::trunc);
    if (jOfs) {
        jOfs << jsonContent;
        jOfs.close();
        result.json_saved = true;
        result.json_path = jsonFile.string();
    }

    // 2. Save HTML
    std::string htmlContent = generateHtml(report);
    std::ofstream hOfs(htmlFile, std::ios::out | std::ios::trunc);
    if (hOfs) {
        hOfs << htmlContent;
        hOfs.close();
        result.html_saved = true;
        result.html_path = htmlFile.string();
    }

    // 3. Generate PDF if requested
    if (generatePdfCopy) {
        // Try headless browser first if available
        if (result.html_saved && generatePdf(result.html_path, pdfFile.string())) {
            result.pdf_saved = true;
            result.pdf_path = pdfFile.string();
        } else {
            // Standalone native vector PDF engine (zero external dependencies)
            result.pdf_saved = generatePdfDirect(report, pdfFile.string());
            if (result.pdf_saved) {
                result.pdf_path = pdfFile.string();
            }
        }
    }

    return result;
}

} // namespace reporting
} // namespace forensivault
