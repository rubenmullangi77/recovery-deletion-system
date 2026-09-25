#include "test_framework.hpp"
#include "reporting/forensic_report.hpp"
#include "reporting/report_generator.hpp"
#include "forensivault/common/crypto_hash.hpp"
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;
using namespace forensivault::reporting;
using namespace forensivault::core;
using namespace forensivault::logging;

FV_TEST(ForensicReporting, StrictClassificationEnforcesValidationIntegrity) {
    // Rule: Do not claim successful recovery unless validation supports it.

    // 1. Valid + High Confidence -> Successfully Recovered
    auto s1 = ForensicReportBuilder::classifyArtifact("VALID", 95.0, false, {}, {});
    ASSERT_TRUE(s1 == RecoveryStatus::SuccessfullyRecovered);

    // 2. Corrupted / Internal error -> Corrupted (NEVER Successfully Recovered)
    auto s2 = ForensicReportBuilder::classifyArtifact("CORRUPTED", 95.0, true, {}, {"Invalid CRC32 chunk"});
    ASSERT_TRUE(s2 == RecoveryStatus::Corrupted);

    // 3. Truncated stream / Low confidence -> Partially Recovered
    auto s3 = ForensicReportBuilder::classifyArtifact("PARTIAL", 55.0, false, {"Missing EOF marker"}, {});
    ASSERT_TRUE(s3 == RecoveryStatus::PartiallyRecovered);

    // 4. Unvalidated type -> Unvalidated
    auto s4 = ForensicReportBuilder::classifyArtifact("UNVALIDATED", 40.0, false, {}, {});
    ASSERT_TRUE(s4 == RecoveryStatus::Unvalidated);

    // 5. Valid status but low confidence (< 70) -> Conservative Partially Recovered
    auto s5 = ForensicReportBuilder::classifyArtifact("VALID", 65.0, false, {}, {});
    ASSERT_TRUE(s5 == RecoveryStatus::PartiallyRecovered);
}

FV_TEST(ForensicReporting, JsonReportContainsAllMandatoryForensicFields) {
    ForensicReportBuilder builder;

    CaseInfo cInfo;
    cInfo.case_id = "CASE-REPORT-2026";
    cInfo.case_name = "Operation Silent Witness";
    cInfo.investigator_name = "Inspector Priya Sen";
    cInfo.agency = "Forensic Science Laboratory";
    cInfo.description = "Deep forensic triage of seized storage media";
    builder.setCaseInfo(cInfo);

    AcquisitionMetadata acq;
    acq.evidence_id = "EVD-REP-001";
    acq.source_path = "D:/Evidence/target_drive.img";
    acq.total_bytes = 1048576; // 1 MB
    acq.total_sectors = 2048;
    acq.sector_size = 512;
    acq.intake_sha256 = "111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000";
    acq.intake_md5 = "0123456789abcdef0123456789abcdef";
    acq.acquisition_timestamp_iso = "2026-09-09T18:30:00.000Z";
    acq.acquiring_examiner = "Inspector Priya Sen";
    builder.setAcquisition(acq);

    // Pre and post hashes match -> verified unmodified
    builder.setEvidenceHashes(acq.intake_sha256, acq.intake_sha256);

    // Add Recovered Items
    ReportItem it1;
    it1.item_id = 1;
    it1.filename = "evidence_photo.jpg";
    it1.relative_path = "carved/JPG/evidence_photo.jpg";
    it1.file_type = "JPEG";
    it1.extension = "jpg";
    it1.byte_offset = 2048;
    it1.size_bytes = 45000;
    it1.sha256_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    it1.recovery_source = "Raw Signature Carving";
    it1.confidence_score = 94.0;
    it1.confidence_level = "High";
    it1.recovery_status = RecoveryStatus::SuccessfullyRecovered;
    it1.parser_validation_result = "VALID";
    it1.reasons = {"Valid SOI marker", "Valid EOI marker"};
    builder.addRecoveredItem(it1);

    ReportItem it2;
    it2.item_id = 2;
    it2.filename = "damaged_stream.png";
    it2.relative_path = "carved/PNG/damaged_stream.png";
    it2.file_type = "PNG";
    it2.extension = "png";
    it2.byte_offset = 65536;
    it2.size_bytes = 12000;
    it2.sha256_hash = "9999888877776666555544443333222211110000aaaabbbbccccddddeeeeffff";
    it2.recovery_source = "Raw Signature Carving";
    it2.confidence_score = 25.0;
    it2.confidence_level = "Very Low";
    it2.recovery_status = RecoveryStatus::Corrupted;
    it2.parser_validation_result = "INVALID";
    it2.errors = {"CRC32 mismatch in IDAT chunk"};
    builder.addRecoveredItem(it2);

    // Add Sanitization Record
    SanitizationRecord san;
    san.target_path = "D:/Disposable/temp_wipe.img";
    san.method_standard = "NIST SP 800-88 Rev 1 Clear";
    san.passes_completed = 1;
    san.bytes_sanitized = 65536;
    san.measured_entropy = 0.0000;
    san.pattern_match_rate = 100.0;
    san.verified_compliant = true;
    builder.addSanitizationRecord(san);

    // Build report
    auto report = builder.build();

    // Verify statistics calculation
    ASSERT_EQ(report.statistics.total_artifacts_discovered, 2ULL);
    ASSERT_EQ(report.statistics.count_successful, 1ULL);
    ASSERT_EQ(report.statistics.count_corrupted, 1ULL);
    ASSERT_EQ(report.statistics.confidence_high, 1U);
    ASSERT_EQ(report.statistics.confidence_very_low, 1U);

    // Generate JSON
    std::string json = ReportGenerator::generateJson(report);
    ASSERT_FALSE(json.empty());

    // Verify required fields present in JSON
    ASSERT_TRUE(json.find("\"case_id\": \"CASE-REPORT-2026\"") != std::string::npos);
    ASSERT_TRUE(json.find("\"evidence_id\": \"EVD-REP-001\"") != std::string::npos);
    ASSERT_TRUE(json.find("\"evidence_unmodified\": true") != std::string::npos);
    ASSERT_TRUE(json.find("\"intake_sha256\": \"111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000\"") != std::string::npos);
    ASSERT_TRUE(json.find("\"recovery_status\": \"Successfully Recovered\"") != std::string::npos);
    ASSERT_TRUE(json.find("\"recovery_status\": \"Corrupted\"") != std::string::npos);
    ASSERT_TRUE(json.find("\"method_standard\": \"NIST SP 800-88 Rev 1 Clear\"") != std::string::npos);
}

FV_TEST(ForensicReporting, HtmlReportAndHeadlessPdfGeneration) {
    ForensicReportBuilder builder;

    CaseInfo cInfo;
    cInfo.case_id = "CASE-DOC-TEST";
    cInfo.case_name = "Legal Admissibility Evidence Package";
    cInfo.investigator_name = "Senior Examiner K. Roy";
    cInfo.agency = "National Cyber Forensics Hub";
    builder.setCaseInfo(cInfo);

    AcquisitionMetadata acq;
    acq.evidence_id = "EVD-HDD-09";
    acq.source_path = "test_data/disposable/evidence.img";
    acq.total_bytes = 65536;
    acq.intake_sha256 = "33334444555566667777888899990000aaaabbbbccccddddeeeeffff11112222";
    builder.setAcquisition(acq);
    builder.setEvidenceHashes(acq.intake_sha256, acq.intake_sha256);

    ReportItem it;
    it.item_id = 1;
    it.filename = "confidential_document.pdf";
    it.relative_path = "carved/PDF/confidential_document.pdf";
    it.file_type = "PDF";
    it.extension = "pdf";
    it.byte_offset = 4096;
    it.size_bytes = 18450;
    it.sha256_hash = "7777888899990000aaaabbbbccccddddeeeeffff111122223333444455556666";
    it.recovery_source = "Raw Signature Carving";
    it.confidence_score = 92.5;
    it.confidence_level = "High";
    it.recovery_status = RecoveryStatus::SuccessfullyRecovered;
    it.parser_validation_result = "VALID";
    builder.addRecoveredItem(it);

    auto report = builder.build();

    // 1. Generate HTML
    std::string html = ReportGenerator::generateHtml(report);
    ASSERT_FALSE(html.empty());
    ASSERT_TRUE(html.find("ForensiVault") != std::string::npos);
    ASSERT_TRUE(html.find("confidential_document.pdf") != std::string::npos);
    ASSERT_TRUE(html.find("Successfully Recovered") != std::string::npos);

    // 2. Test saving report package (JSON + HTML + PDF)
    std::string outDir = "test_data/disposable/reports_test";
    fs::remove_all(outDir);

    auto pkg = ReportGenerator::saveReportPackage(report, outDir, true);
    ASSERT_TRUE(pkg.json_saved);
    ASSERT_TRUE(pkg.html_saved);
    ASSERT_TRUE(fs::exists(pkg.json_path));
    ASSERT_TRUE(fs::exists(pkg.html_path));

    // PDF generation depends on MS Edge headless availability
    if (pkg.pdf_saved) {
        ASSERT_TRUE(fs::exists(pkg.pdf_path));
        ASSERT_TRUE(fs::file_size(pkg.pdf_path) > 0);
    }

    fs::remove_all(outDir);
}
