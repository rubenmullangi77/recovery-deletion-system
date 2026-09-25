#pragma once

#include "logging/audit_logger.hpp"
#include <string>
#include <vector>
#include <filesystem>

namespace forensivault {
namespace core {

struct CaseInfo {
    std::string case_id;
    std::string case_name;
    std::string investigator_name;
    std::string agency;
    std::string description;
    std::string created_timestamp_iso;
    std::string case_root_path;

    std::string toJson() const;
};

struct EvidenceItem {
    std::string evidence_id;
    std::string filename;
    std::string filepath;
    uint64_t size_bytes{0};
    std::string sha256_hash;
    std::string acquired_timestamp_iso;
    std::string source_device;
    std::string notes;

    std::string toJson() const;
};

class CaseManager {
public:
    CaseManager() = default;
    explicit CaseManager(const std::string& caseRootPath);

    /**
     * @brief Creates a standard forensic workspace layout:
     *   <root>/
     *     case/
     *     evidence/
     *     recovered/
     *       active/
     *       deleted/
     *       carved/
     *     reports/
     *     logs/
     */
    static bool initializeWorkspace(const std::string& caseRootPath, const CaseInfo& info);

    /**
     * @brief Opens an existing workspace.
     */
    bool openWorkspace(const std::string& caseRootPath);

    /**
     * @brief Computes SHA-256 hash and registers an evidence file into the evidence/ directory.
     * Guarantees read-only handling.
     */
    EvidenceItem registerEvidence(const std::string& sourceImagePath,
                                 const std::string& evidenceId,
                                 const std::string& notes = "");

    /**
     * @brief Verifies that an evidence image's current SHA-256 hash matches its registered hash.
     */
    bool verifyEvidenceIntegrity(const std::string& evidenceId, std::string* outCurrentHash = nullptr) const;

    /**
     * @brief Record chain of custody event for an evidence item.
     */
    void addCustodyRecord(const std::string& evidenceId,
                          const std::string& action,
                          const std::string& custodian,
                          const std::string& location,
                          const std::string& notes);

    // Path accessors
    std::string caseRoot() const { return case_root_; }
    std::string caseDir() const { return (std::filesystem::path(case_root_) / "case").string(); }
    std::string evidenceDir() const { return (std::filesystem::path(case_root_) / "evidence").string(); }
    std::string recoveredDir() const { return (std::filesystem::path(case_root_) / "recovered").string(); }
    std::string reportsDir() const { return (std::filesystem::path(case_root_) / "reports").string(); }
    std::string logsDir() const { return (std::filesystem::path(case_root_) / "logs").string(); }
    std::string auditLogPath() const { return (std::filesystem::path(logsDir()) / "audit_journal.jsonl").string(); }

    const CaseInfo& getCaseInfo() const { return case_info_; }
    std::vector<EvidenceItem> getEvidenceList() const { return evidence_list_; }
    std::vector<logging::CustodyEvent> getCustodyHistory(const std::string& evidenceId) const;

    /**
     * @brief Export formal structured forensic report to reports/
     */
    bool saveReport(const std::string& reportFilename, const std::string& reportContent) const;

private:
    std::string case_root_;
    CaseInfo case_info_;
    std::vector<EvidenceItem> evidence_list_;
    std::vector<logging::CustodyEvent> custody_log_;

    void saveMetadata();
    void loadMetadata();
};

} // namespace core
} // namespace forensivault
