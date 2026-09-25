#include "core/case_manager.hpp"
#include "forensivault/common/crypto_hash.hpp"
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>

namespace fs = std::filesystem;

namespace forensivault {
namespace core {

namespace {

std::string escapeJson(const std::string& s) {
    std::ostringstream o;
    for (char c : s) {
        if (c == '"') o << "\\\"";
        else if (c == '\\') o << "\\\\";
        else if (c == '\n') o << "\\n";
        else if (c == '\r') o << "\\r";
        else if (c == '\t') o << "\\t";
        else o << c;
    }
    return o.str();
}

std::string computeFileSha256(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) return "";

    CryptoHash::Sha256Context ctx;

    const size_t bufSize = 64 * 1024;
    std::vector<uint8_t> buffer(bufSize);
    while (file.good()) {
        file.read(reinterpret_cast<char*>(buffer.data()), bufSize);
        std::streamsize bytesRead = file.gcount();
        if (bytesRead > 0) {
            ctx.update(buffer.data(), static_cast<size_t>(bytesRead));
        }
    }
    file.close();
    return ctx.finalize();
}

} // anonymous namespace

std::string CaseInfo::toJson() const {
    std::ostringstream ss;
    ss << "{"
       << "\"case_id\":\"" << escapeJson(case_id) << "\","
       << "\"case_name\":\"" << escapeJson(case_name) << "\","
       << "\"investigator_name\":\"" << escapeJson(investigator_name) << "\","
       << "\"agency\":\"" << escapeJson(agency) << "\","
       << "\"description\":\"" << escapeJson(description) << "\","
       << "\"created_timestamp_iso\":\"" << escapeJson(created_timestamp_iso) << "\","
       << "\"case_root_path\":\"" << escapeJson(case_root_path) << "\""
       << "}";
    return ss.str();
}

std::string EvidenceItem::toJson() const {
    std::ostringstream ss;
    ss << "{"
       << "\"evidence_id\":\"" << escapeJson(evidence_id) << "\","
       << "\"filename\":\"" << escapeJson(filename) << "\","
       << "\"filepath\":\"" << escapeJson(filepath) << "\","
       << "\"size_bytes\":" << size_bytes << ","
       << "\"sha256_hash\":\"" << sha256_hash << "\","
       << "\"acquired_timestamp_iso\":\"" << escapeJson(acquired_timestamp_iso) << "\","
       << "\"source_device\":\"" << escapeJson(source_device) << "\","
       << "\"notes\":\"" << escapeJson(notes) << "\""
       << "}";
    return ss.str();
}

CaseManager::CaseManager(const std::string& caseRootPath) {
    openWorkspace(caseRootPath);
}

bool CaseManager::initializeWorkspace(const std::string& caseRootPath, const CaseInfo& info) {
    std::error_code ec;
    fs::path root(caseRootPath);

    // Standard forensic workspace layout:
    //   case/
    //   evidence/
    //   recovered/
    //     active/
    //     deleted/
    //     carved/
    //   reports/
    //   logs/
    fs::create_directories(root / "case", ec);
    fs::create_directories(root / "evidence", ec);
    fs::create_directories(root / "recovered" / "active", ec);
    fs::create_directories(root / "recovered" / "deleted", ec);
    fs::create_directories(root / "recovered" / "carved", ec);
    fs::create_directories(root / "reports", ec);
    fs::create_directories(root / "logs", ec);

    if (ec) return false;

    CaseInfo updatedInfo = info;
    updatedInfo.case_root_path = root.string();
    if (updatedInfo.created_timestamp_iso.empty()) {
        updatedInfo.created_timestamp_iso = logging::AuditLogger::currentTimestampIso();
    }

    fs::path metaPath = root / "case" / "case_metadata.json";
    std::ofstream ofs(metaPath, std::ios::out | std::ios::trunc);
    if (!ofs) return false;
    ofs << updatedInfo.toJson() << "\n";
    ofs.close();

    // Log initialization in case audit log
    logging::AuditEntry initEntry;
    initEntry.case_id = updatedInfo.case_id;
    initEntry.operation_id = "OP-CASE-INIT-001";
    initEntry.operator_name = updatedInfo.investigator_name;
    initEntry.operation_type = "CASE_WORKSPACE_INITIALIZED";
    initEntry.source_identifier = root.string();
    initEntry.status = "SUCCESS";
    initEntry.details = "Forensic case workspace layout created with evidence, recovered, reports, and logs folders.";

    logging::CustodyEvent ev;
    ev.timestamp_iso = updatedInfo.created_timestamp_iso;
    ev.action = "CASE_CREATED";
    ev.custodian = updatedInfo.investigator_name;
    ev.location = updatedInfo.agency;
    ev.notes = "Case opened: " + updatedInfo.case_name;
    initEntry.chain_of_custody.push_back(ev);

    auto logged = logging::AuditLogger::getInstance().logForensicOperation(initEntry);
    logging::AuditLogger::getInstance().saveToFile((root / "logs" / "audit_journal.jsonl").string());

    return true;
}

bool CaseManager::openWorkspace(const std::string& caseRootPath) {
    case_root_ = caseRootPath;
    fs::path root(caseRootPath);
    if (!fs::exists(root / "case" / "case_metadata.json")) {
        return false;
    }

    loadMetadata();
    return true;
}

void CaseManager::saveMetadata() {
    fs::path metaPath = fs::path(case_root_) / "case" / "case_metadata.json";
    std::ofstream ofs(metaPath, std::ios::out | std::ios::trunc);
    if (ofs) {
        ofs << case_info_.toJson() << "\n";
    }

    // Save evidence catalog
    fs::path evPath = fs::path(case_root_) / "case" / "evidence_catalog.json";
    std::ofstream evOfs(evPath, std::ios::out | std::ios::trunc);
    if (evOfs) {
        evOfs << "[\n";
        for (size_t i = 0; i < evidence_list_.size(); ++i) {
            evOfs << "  " << evidence_list_[i].toJson() << (i + 1 < evidence_list_.size() ? ",\n" : "\n");
        }
        evOfs << "]\n";
    }
}

void CaseManager::loadMetadata() {
    fs::path metaPath = fs::path(case_root_) / "case" / "case_metadata.json";
    std::ifstream ifs(metaPath);
    if (ifs) {
        std::string line;
        std::getline(ifs, line);
        auto extractStr = [&](const std::string& key) -> std::string {
            std::string pattern = "\"" + key + "\":\"";
            size_t pos = line.find(pattern);
            if (pos == std::string::npos) return "";
            size_t start = pos + pattern.length();
            size_t end = line.find('"', start);
            if (end == std::string::npos) return "";
            return line.substr(start, end - start);
        };
        case_info_.case_id = extractStr("case_id");
        case_info_.case_name = extractStr("case_name");
        case_info_.investigator_name = extractStr("investigator_name");
        case_info_.agency = extractStr("agency");
        case_info_.description = extractStr("description");
        case_info_.created_timestamp_iso = extractStr("created_timestamp_iso");
        case_info_.case_root_path = extractStr("case_root_path");
    }
}

EvidenceItem CaseManager::registerEvidence(const std::string& sourceImagePath,
                                           const std::string& evidenceId,
                                           const std::string& notes) {
    EvidenceItem item;
    item.evidence_id = evidenceId;
    item.source_device = sourceImagePath;
    item.notes = notes;
    item.acquired_timestamp_iso = logging::AuditLogger::currentTimestampIso();

    std::error_code ec;
    item.size_bytes = fs::file_size(sourceImagePath, ec);
    item.filename = fs::path(sourceImagePath).filename().string();

    // Compute cryptographic hash of source evidence (READ-ONLY)
    item.sha256_hash = computeFileSha256(sourceImagePath);

    // Target evidence directory in case workspace
    fs::path targetEvidence = fs::path(evidenceDir()) / item.filename;

    // If source is not already inside evidenceDir, copy or link it
    if (fs::absolute(sourceImagePath) != fs::absolute(targetEvidence)) {
        fs::copy_file(sourceImagePath, targetEvidence, fs::copy_options::overwrite_existing, ec);
        item.filepath = targetEvidence.string();
    } else {
        item.filepath = sourceImagePath;
    }

    evidence_list_.push_back(item);
    saveMetadata();

    // Add initial custody record
    addCustodyRecord(evidenceId, "EVIDENCE_ACQUIRED", case_info_.investigator_name,
                     case_info_.agency, "Acquired evidence image: " + item.filename + " [SHA-256: " + item.sha256_hash + "]");

    // Record in cryptographically chained audit logger
    logging::AuditEntry entry;
    entry.case_id = case_info_.case_id;
    entry.evidence_id = evidenceId;
    entry.operation_id = "OP-ACQ-" + evidenceId;
    entry.operator_name = case_info_.investigator_name;
    entry.operation_type = "EVIDENCE_INGESTED";
    entry.source_identifier = item.filepath;
    entry.source_sha256 = item.sha256_hash;
    entry.status = "SUCCESS";
    entry.details = "Evidence image ingested into case repository. Size: " + std::to_string(item.size_bytes) + " bytes.";
    
    logging::CustodyEvent ce;
    ce.timestamp_iso = item.acquired_timestamp_iso;
    ce.action = "ACQUISITION";
    ce.custodian = case_info_.investigator_name;
    ce.location = case_info_.agency;
    ce.notes = "Intake hash verified: " + item.sha256_hash;
    entry.chain_of_custody.push_back(ce);

    logging::AuditLogger::getInstance().logForensicOperation(entry);
    logging::AuditLogger::getInstance().saveToFile(auditLogPath());

    return item;
}

bool CaseManager::verifyEvidenceIntegrity(const std::string& evidenceId, std::string* outCurrentHash) const {
    for (const auto& ev : evidence_list_) {
        if (ev.evidence_id == evidenceId) {
            std::string current = computeFileSha256(ev.filepath);
            if (outCurrentHash) *outCurrentHash = current;
            return (!current.empty() && current == ev.sha256_hash);
        }
    }
    return false;
}

void CaseManager::addCustodyRecord(const std::string& evidenceId,
                                   const std::string& action,
                                   const std::string& custodian,
                                   const std::string& location,
                                   const std::string& notes) {
    logging::CustodyEvent ev;
    ev.timestamp_iso = logging::AuditLogger::currentTimestampIso();
    ev.action = action;
    ev.custodian = custodian;
    ev.location = location;
    ev.notes = "[" + evidenceId + "] " + notes;

    custody_log_.push_back(ev);
}

std::vector<logging::CustodyEvent> CaseManager::getCustodyHistory(const std::string& evidenceId) const {
    std::vector<logging::CustodyEvent> filtered;
    std::string tag = "[" + evidenceId + "]";
    for (const auto& c : custody_log_) {
        if (c.notes.find(tag) != std::string::npos || evidenceId.empty()) {
            filtered.push_back(c);
        }
    }
    return filtered;
}

bool CaseManager::saveReport(const std::string& reportFilename, const std::string& reportContent) const {
    fs::path repPath = fs::path(reportsDir()) / reportFilename;
    std::ofstream ofs(repPath, std::ios::out | std::ios::trunc);
    if (!ofs) return false;
    ofs << reportContent;
    ofs.close();
    return true;
}

} // namespace core
} // namespace forensivault
