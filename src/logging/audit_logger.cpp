#include "logging/audit_logger.hpp"
#include "forensivault/common/crypto_hash.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>

namespace forensivault {
namespace logging {

namespace {
const std::string GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

std::string escapeJson(const std::string& s) {
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

std::string unescapeJson(const std::string& s) {
    std::string out;
    out.reserve(s.length());
    for (size_t i = 0; i < s.length(); ++i) {
        if (s[i] == '\\' && i + 1 < s.length()) {
            char next = s[++i];
            if (next == '"') out += '"';
            else if (next == '\\') out += '\\';
            else if (next == 'n') out += '\n';
            else if (next == 'r') out += '\r';
            else if (next == 't') out += '\t';
            else out += next;
        } else {
            out += s[i];
        }
    }
    return out;
}
} // anonymous namespace

std::string RecoveredArtifactRecord::toJson() const {
    std::ostringstream ss;
    ss << "{"
       << "\"file_id\":" << file_id << ","
       << "\"filename\":\"" << escapeJson(filename) << "\","
       << "\"relative_path\":\"" << escapeJson(relative_path) << "\","
       << "\"file_type\":\"" << escapeJson(file_type) << "\","
       << "\"extension\":\"" << escapeJson(extension) << "\","
       << "\"byte_offset\":" << byte_offset << ","
       << "\"size_bytes\":" << size_bytes << ","
       << "\"sha256_hash\":\"" << sha256_hash << "\","
       << "\"confidence_score\":" << std::fixed << std::setprecision(2) << confidence_score << ","
       << "\"confidence_level\":\"" << escapeJson(confidence_level) << "\","
       << "\"validation_status\":\"" << escapeJson(validation_status) << "\",";
    
    // reasons array
    ss << "\"reasons\":[";
    for (size_t i = 0; i < reasons.size(); ++i) {
        ss << "\"" << escapeJson(reasons[i]) << "\"" << (i + 1 < reasons.size() ? "," : "");
    }
    ss << "],";

    // warnings array
    ss << "\"warnings\":[";
    for (size_t i = 0; i < warnings.size(); ++i) {
        ss << "\"" << escapeJson(warnings[i]) << "\"" << (i + 1 < warnings.size() ? "," : "");
    }
    ss << "]}";
    return ss.str();
}

std::string CustodyEvent::toJson() const {
    std::ostringstream ss;
    ss << "{"
       << "\"timestamp\":\"" << escapeJson(timestamp_iso) << "\","
       << "\"action\":\"" << escapeJson(action) << "\","
       << "\"custodian\":\"" << escapeJson(custodian) << "\","
       << "\"location\":\"" << escapeJson(location) << "\","
       << "\"notes\":\"" << escapeJson(notes) << "\""
       << "}";
    return ss.str();
}

std::string AuditEntry::toJson() const {
    std::ostringstream ss;
    ss << "{"
       << "\"entry_id\":" << entry_id << ","
       << "\"timestamp\":\"" << escapeJson(timestamp_iso) << "\","
       << "\"case_id\":\"" << escapeJson(case_id) << "\","
       << "\"evidence_id\":\"" << escapeJson(evidence_id) << "\","
       << "\"operation_id\":\"" << escapeJson(operation_id) << "\","
       << "\"operator_name\":\"" << escapeJson(operator_name) << "\","
       << "\"tool_version\":\"" << escapeJson(tool_version) << "\","
       << "\"operation_type\":\"" << escapeJson(operation_type) << "\","
       << "\"source_identifier\":\"" << escapeJson(source_identifier) << "\","
       << "\"source_sha256\":\"" << escapeJson(source_sha256) << "\","
       << "\"method\":\"" << escapeJson(method) << "\","
       << "\"status\":\"" << escapeJson(status) << "\","
       << "\"details\":\"" << escapeJson(details) << "\",";

    // Recovered Artifacts list
    ss << "\"recovered_artifacts\":[";
    for (size_t i = 0; i < recovered_artifacts.size(); ++i) {
        ss << recovered_artifacts[i].toJson() << (i + 1 < recovered_artifacts.size() ? "," : "");
    }
    ss << "],";

    // Verification results
    ss << "\"verification_results\":\"" << escapeJson(verification_results) << "\",";

    // Warnings and errors
    ss << "\"warnings_and_errors\":[";
    for (size_t i = 0; i < warnings_and_errors.size(); ++i) {
        ss << "\"" << escapeJson(warnings_and_errors[i]) << "\"" << (i + 1 < warnings_and_errors.size() ? "," : "");
    }
    ss << "],";

    // Chain of Custody
    ss << "\"chain_of_custody\":[";
    for (size_t i = 0; i < chain_of_custody.size(); ++i) {
        ss << chain_of_custody[i].toJson() << (i + 1 < chain_of_custody.size() ? "," : "");
    }
    ss << "],";

    // Chaining hashes
    ss << "\"previous_hash\":\"" << previous_hash << "\","
       << "\"entry_hash\":\"" << entry_hash << "\""
       << "}";
    return ss.str();
}

AuditLogger& AuditLogger::getInstance() {
    static AuditLogger instance;
    return instance;
}

AuditLogger::AuditLogger() : last_hash_(GENESIS_HASH) {}

std::string AuditLogger::currentTimestampIso() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    std::tm tmBuf{};
#if defined(_WIN32)
    gmtime_s(&tmBuf, &now_c);
#else
    gmtime_r(&now_c, &tmBuf);
#endif

    std::ostringstream ss;
    ss << std::put_time(&tmBuf, "%Y-%m-%dT%H:%M:%S")
       << "." << std::setfill('0') << std::setw(3) << ms.count() << "Z";
    return ss.str();
}

std::string AuditLogger::computeEntryHash(const AuditEntry& entry) {
    std::ostringstream ss;
    ss << entry.previous_hash << "|"
       << entry.entry_id << "|"
       << entry.timestamp_iso << "|"
       << entry.case_id << "|"
       << entry.evidence_id << "|"
       << entry.operation_id << "|"
       << entry.operator_name << "|"
       << entry.tool_version << "|"
       << entry.operation_type << "|"
       << entry.source_identifier << "|"
       << entry.source_sha256 << "|"
       << entry.method << "|"
       << entry.status << "|"
       << entry.details << "|";

    // Artifacts components in hash
    for (const auto& a : entry.recovered_artifacts) {
        ss << a.file_id << ":" << a.filename << ":" << a.byte_offset << ":"
           << a.size_bytes << ":" << a.sha256_hash << ":"
           << static_cast<int>(a.confidence_score * 100) << "|";
    }

    // Custody components in hash
    for (const auto& c : entry.chain_of_custody) {
        ss << c.timestamp_iso << ":" << c.action << ":" << c.custodian << "|";
    }

    // Warnings and errors
    for (const auto& w : entry.warnings_and_errors) {
        ss << w << "|";
    }

    ss << entry.verification_results;

    return CryptoHash::sha256(ss.str());
}

AuditEntry AuditLogger::logEvent(const std::string& opType,
                                 const std::string& targetPath,
                                 const std::string& method,
                                 const std::string& status,
                                 const std::string& details) {
    AuditEntry entry;
    entry.operation_type = opType;
    entry.source_identifier = targetPath;
    entry.method = method;
    entry.status = status;
    entry.details = details;

    return logForensicOperation(entry);
}

AuditEntry AuditLogger::logForensicOperation(const AuditEntry& draftEntry) {
    std::lock_guard<std::mutex> lock(mutex_);

    AuditEntry entry = draftEntry;
    entry.entry_id = entries_.size() + 1;
    if (entry.timestamp_iso.empty()) {
        entry.timestamp_iso = currentTimestampIso();
    }
    if (entry.tool_version.empty()) {
        entry.tool_version = "ForensiVault v1.0.0";
    }
    entry.previous_hash = last_hash_;
    entry.entry_hash = computeEntryHash(entry);

    last_hash_ = entry.entry_hash;
    entries_.push_back(entry);

    return entry;
}

bool AuditLogger::verifyChain(size_t* outBrokenIndex) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string expectedPrev = GENESIS_HASH;

    for (size_t i = 0; i < entries_.size(); ++i) {
        const auto& entry = entries_[i];

        // 1. Verify previous hash link
        if (entry.previous_hash != expectedPrev) {
            if (outBrokenIndex) *outBrokenIndex = i;
            return false;
        }

        // 2. Recompute and verify current entry hash
        std::string expectedHash = computeEntryHash(entry);
        if (entry.entry_hash != expectedHash) {
            if (outBrokenIndex) *outBrokenIndex = i;
            return false;
        }

        expectedPrev = entry.entry_hash;
    }

    return true;
}

std::vector<AuditEntry> AuditLogger::getEntries() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_;
}

void AuditLogger::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.clear();
    last_hash_ = GENESIS_HASH;
}

bool AuditLogger::saveToFile(const std::string& filepath) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ofstream ofs(filepath, std::ios::out | std::ios::trunc);
    if (!ofs) return false;

    for (const auto& e : entries_) {
        ofs << e.toJson() << "\n";
    }
    return ofs.good();
}

bool AuditLogger::loadFromFile(const std::string& filepath) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ifstream ifs(filepath);
    if (!ifs) return false;

    std::vector<AuditEntry> loaded;
    std::string line;
    while (std::getline(ifs, line)) {
        if (line.empty()) continue;
        AuditEntry e;
        auto extractStr = [&](const std::string& key) -> std::string {
            std::string pattern = "\"" + key + "\":\"";
            size_t pos = line.find(pattern);
            if (pos == std::string::npos) return "";
            size_t start = pos + pattern.length();
            size_t curr = start;
            while (curr < line.length()) {
                if (line[curr] == '"' && line[curr - 1] != '\\') {
                    break;
                }
                curr++;
            }
            if (curr >= line.length()) return "";
            return unescapeJson(line.substr(start, curr - start));
        };
        auto extractNum = [&](const std::string& key) -> uint64_t {
            std::string pattern = "\"" + key + "\":";
            size_t pos = line.find(pattern);
            if (pos == std::string::npos) return 0;
            size_t start = pos + pattern.length();
            size_t end = line.find_first_of(",}", start);
            if (end == std::string::npos) return 0;
            return std::stoull(line.substr(start, end - start));
        };

        e.entry_id = extractNum("entry_id");
        e.timestamp_iso = extractStr("timestamp");
        e.case_id = extractStr("case_id");
        e.evidence_id = extractStr("evidence_id");
        e.operation_id = extractStr("operation_id");
        e.operator_name = extractStr("operator_name");
        e.tool_version = extractStr("tool_version");
        e.operation_type = extractStr("operation_type");
        e.source_identifier = extractStr("source_identifier");
        if (e.source_identifier.empty()) {
            e.source_identifier = extractStr("target_path"); // backward compatibility
        }
        e.source_sha256 = extractStr("source_sha256");
        e.method = extractStr("method");
        e.status = extractStr("status");
        e.details = extractStr("details");
        e.verification_results = extractStr("verification_results");
        e.previous_hash = extractStr("previous_hash");
        e.entry_hash = extractStr("entry_hash");

        // Sub-string extract helper for nested JSON blocks
        auto extractSubStr = [](const std::string& block, const std::string& key) -> std::string {
            std::string pattern = "\"" + key + "\":\"";
            size_t pos = block.find(pattern);
            if (pos == std::string::npos) return "";
            size_t start = pos + pattern.length();
            size_t curr = start;
            while (curr < block.length()) {
                if (block[curr] == '"' && (curr == 0 || block[curr - 1] != '\\')) break;
                curr++;
            }
            if (curr >= block.length()) return "";
            return unescapeJson(block.substr(start, curr - start));
        };

        auto extractSubNum = [](const std::string& block, const std::string& key) -> uint64_t {
            std::string pattern = "\"" + key + "\":";
            size_t pos = block.find(pattern);
            if (pos == std::string::npos) return 0;
            size_t start = pos + pattern.length();
            size_t end = block.find_first_of(",}", start);
            if (end == std::string::npos) return 0;
            try {
                return std::stoull(block.substr(start, end - start));
            } catch (...) {
                return 0;
            }
        };

        auto extractSubDouble = [](const std::string& block, const std::string& key) -> double {
            std::string pattern = "\"" + key + "\":";
            size_t pos = block.find(pattern);
            if (pos == std::string::npos) return 0.0;
            size_t start = pos + pattern.length();
            size_t end = block.find_first_of(",}", start);
            if (end == std::string::npos) return 0.0;
            try {
                return std::stod(block.substr(start, end - start));
            } catch (...) {
                return 0.0;
            }
        };

        auto extractArraySection = [&](const std::string& key) -> std::string {
            std::string pattern = "\"" + key + "\":[";
            size_t pos = line.find(pattern);
            if (pos == std::string::npos) return "";
            size_t start = pos + pattern.length() - 1; // points to '['
            int depth = 0;
            for (size_t i = start; i < line.length(); ++i) {
                if (line[i] == '[') depth++;
                else if (line[i] == ']') {
                    depth--;
                    if (depth == 0) {
                        return line.substr(start + 1, i - (start + 1));
                    }
                }
            }
            return "";
        };

        // Parse recovered_artifacts array
        std::string artArray = extractArraySection("recovered_artifacts");
        if (!artArray.empty()) {
            size_t idx = 0;
            while (idx < artArray.length()) {
                size_t objStart = artArray.find('{', idx);
                if (objStart == std::string::npos) break;
                int bDepth = 0;
                size_t objEnd = std::string::npos;
                for (size_t j = objStart; j < artArray.length(); ++j) {
                    if (artArray[j] == '{') bDepth++;
                    else if (artArray[j] == '}') {
                        bDepth--;
                        if (bDepth == 0) {
                            objEnd = j;
                            break;
                        }
                    }
                }
                if (objEnd == std::string::npos) break;
                std::string block = artArray.substr(objStart, objEnd - objStart + 1);

                RecoveredArtifactRecord a;
                a.file_id = extractSubNum(block, "file_id");
                a.filename = extractSubStr(block, "filename");
                a.relative_path = extractSubStr(block, "relative_path");
                a.file_type = extractSubStr(block, "file_type");
                a.extension = extractSubStr(block, "extension");
                a.byte_offset = extractSubNum(block, "byte_offset");
                a.size_bytes = extractSubNum(block, "size_bytes");
                a.sha256_hash = extractSubStr(block, "sha256_hash");
                a.confidence_score = extractSubDouble(block, "confidence_score");
                a.confidence_level = extractSubStr(block, "confidence_level");
                a.validation_status = extractSubStr(block, "validation_status");
                e.recovered_artifacts.push_back(a);

                idx = objEnd + 1;
            }
        }

        // Parse chain_of_custody array
        std::string custArray = extractArraySection("chain_of_custody");
        if (!custArray.empty()) {
            size_t idx = 0;
            while (idx < custArray.length()) {
                size_t objStart = custArray.find('{', idx);
                if (objStart == std::string::npos) break;
                size_t objEnd = custArray.find('}', objStart);
                if (objEnd == std::string::npos) break;
                std::string block = custArray.substr(objStart, objEnd - objStart + 1);

                CustodyEvent ce;
                ce.timestamp_iso = extractSubStr(block, "timestamp");
                ce.action = extractSubStr(block, "action");
                ce.custodian = extractSubStr(block, "custodian");
                ce.location = extractSubStr(block, "location");
                ce.notes = extractSubStr(block, "notes");
                e.chain_of_custody.push_back(ce);

                idx = objEnd + 1;
            }
        }

        // Parse warnings_and_errors array
        std::string warnArray = extractArraySection("warnings_and_errors");
        if (!warnArray.empty()) {
            size_t idx = 0;
            while (idx < warnArray.length()) {
                size_t sStart = warnArray.find('"', idx);
                if (sStart == std::string::npos) break;
                size_t sEnd = sStart + 1;
                while (sEnd < warnArray.length()) {
                    if (warnArray[sEnd] == '"' && warnArray[sEnd - 1] != '\\') break;
                    sEnd++;
                }
                if (sEnd >= warnArray.length()) break;
                e.warnings_and_errors.push_back(unescapeJson(warnArray.substr(sStart + 1, sEnd - sStart - 1)));
                idx = sEnd + 1;
            }
        }

        loaded.push_back(e);
    }

    entries_ = loaded;
    last_hash_ = entries_.empty() ? GENESIS_HASH : entries_.back().entry_hash;
    return true;
}

} // namespace logging
} // namespace forensivault
