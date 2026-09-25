#pragma once

#include "reporting/report_types.hpp"
#include "recovery/recovery_engine.hpp"
#include "core/case_manager.hpp"
#include "logging/audit_logger.hpp"
#include <string>
#include <vector>
#include <memory>

namespace forensivault {
namespace reporting {

class ForensicReportBuilder {
public:
    ForensicReportBuilder();

    ForensicReportBuilder& setCaseInfo(const core::CaseInfo& info);
    ForensicReportBuilder& setAcquisition(const AcquisitionMetadata& acq);
    ForensicReportBuilder& setScanConfig(const ScanConfiguration& config);
    ForensicReportBuilder& setFilesystem(const FilesystemSummary& fs);
    ForensicReportBuilder& setEvidenceHashes(const std::string& preHash, const std::string& postHash);
    ForensicReportBuilder& addRecoveredItem(const ReportItem& item);
    ForensicReportBuilder& addSanitizationRecord(const SanitizationRecord& san);
    ForensicReportBuilder& setAuditTrail(const std::vector<logging::AuditEntry>& trail, bool chainVerified);

    /**
     * @brief Helper to automatically map and classify artifacts from RecoveryEngine report
     */
    ForensicReportBuilder& loadFromRecovery(const core::CaseInfo& caseInfo,
                                           const core::EvidenceItem& evidence,
                                           const recovery::RecoveryReport& recoveryReport,
                                           const std::vector<logging::AuditEntry>& auditTrail);

    /**
     * @brief Strictly classifies an artifact item.
     * Enforces: Never claim successful recovery unless validation supports it.
     */
    static RecoveryStatus classifyArtifact(const std::string& formatValidationStatus,
                                           double confidenceScore,
                                           bool hasStructuralError,
                                           const std::vector<std::string>& warnings,
                                           const std::vector<std::string>& errors);

    ForensicReport build();

private:
    ForensicReport report_;
    void calculateStatistics();
};

} // namespace reporting
} // namespace forensivault
