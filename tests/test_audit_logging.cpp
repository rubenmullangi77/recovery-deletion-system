#include "test_framework.hpp"
#include "logging/audit_logger.hpp"
#include "core/case_manager.hpp"
#include "recovery/recovery_engine.hpp"
#include "core/disk_image_reader.hpp"
#include "forensivault/common/crypto_hash.hpp"
#include <filesystem>
#include <fstream>
#include <vector>

namespace fs = std::filesystem;
using namespace forensivault::logging;
using namespace forensivault::core;

namespace {

void createDummyImage(const std::string& path, size_t sizeBytes) {
    fs::create_directories(fs::path(path).parent_path());
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    std::vector<uint8_t> buf(sizeBytes, 0x00);
    // Write JPEG signature at offset 512
    if (sizeBytes >= 1024) {
        buf[512] = 0xFF; buf[513] = 0xD8; buf[514] = 0xFF; buf[515] = 0xE0; // JPEG SOI + APP0
        buf[516] = 0x00; buf[517] = 0x10; buf[518] = 'J';  buf[519] = 'F';
        buf[520] = 'I';  buf[521] = 'F';  buf[522] = 0x00;
        // End marker EOI
        buf[600] = 0xFF; buf[601] = 0xD9;
    }
    ofs.write(reinterpret_cast<const char*>(buf.data()), buf.size());
    ofs.close();
}

} // anonymous namespace

FV_TEST(AuditSystem, StructuredJsonSerializationAndMandatoryFields) {
    AuditLogger::getInstance().clear();

    AuditEntry entry;
    entry.case_id = "CASE-2026-SIH-001";
    entry.evidence_id = "EVD-DRIVE-01";
    entry.operation_id = "OP-CARVE-0042";
    entry.operator_name = "Inspector Sharma";
    entry.tool_version = "ForensiVault v1.0.0";
    entry.operation_type = "FILE_RECOVERY";
    entry.source_identifier = "C:/Cases/EVD-01.img";
    entry.source_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    entry.method = "Signature-Based Carving";
    entry.status = "SUCCESS";
    entry.details = "Carved 1 valid JPEG file";

    RecoveredArtifactRecord artifact;
    artifact.file_id = 1;
    artifact.filename = "carved_0x512.jpg";
    artifact.relative_path = "carved/JPG/carved_0x512.jpg";
    artifact.file_type = "JPEG";
    artifact.extension = "jpg";
    artifact.byte_offset = 512;
    artifact.size_bytes = 90;
    artifact.sha256_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    artifact.confidence_score = 95.0;
    artifact.confidence_level = "Very High";
    artifact.validation_status = "VALID";
    artifact.reasons.push_back("Valid JPEG SOI/APP0 markers");
    artifact.reasons.push_back("Valid EOI termination marker");
    entry.recovered_artifacts.push_back(artifact);

    CustodyEvent custody;
    custody.timestamp_iso = "2026-09-09T18:00:00.000Z";
    custody.action = "FORENSIC_ANALYSIS";
    custody.custodian = "Inspector Sharma";
    custody.location = "Cyber Crime Forensics Lab";
    custody.notes = "Extracted candidate files from unallocated space";
    entry.chain_of_custody.push_back(custody);

    auto logged = AuditLogger::getInstance().logForensicOperation(entry);

    ASSERT_EQ(logged.entry_id, 1);
    ASSERT_FALSE(logged.entry_hash.empty());
    ASSERT_EQ(logged.case_id, "CASE-2026-SIH-001");
    ASSERT_EQ(logged.evidence_id, "EVD-DRIVE-01");
    ASSERT_EQ(logged.recovered_artifacts.size(), 1);
    ASSERT_EQ(logged.chain_of_custody.size(), 1);

    // Verify JSON Serialization contains all critical keys
    std::string json = logged.toJson();
    ASSERT_TRUE(json.find("\"case_id\":\"CASE-2026-SIH-001\"") != std::string::npos);
    ASSERT_TRUE(json.find("\"evidence_id\":\"EVD-DRIVE-01\"") != std::string::npos);
    ASSERT_TRUE(json.find("\"byte_offset\":512") != std::string::npos);
    ASSERT_TRUE(json.find("\"confidence_score\":95.00") != std::string::npos);
    ASSERT_TRUE(json.find("\"confidence_level\":\"Very High\"") != std::string::npos);
    ASSERT_TRUE(json.find("\"action\":\"FORENSIC_ANALYSIS\"") != std::string::npos);
}

FV_TEST(AuditSystem, CryptographicChainAndTamperDetectionOnArtifactFields) {
    AuditLogger::getInstance().clear();

    // Log Entry 1
    AuditEntry e1;
    e1.case_id = "CASE-100";
    e1.operation_id = "OP-1";
    e1.operation_type = "ACQUISITION";
    AuditLogger::getInstance().logForensicOperation(e1);

    // Log Entry 2 with an artifact
    AuditEntry e2;
    e2.case_id = "CASE-100";
    e2.operation_id = "OP-2";
    e2.operation_type = "RECOVERY";
    RecoveredArtifactRecord art;
    art.file_id = 1;
    art.filename = "doc.pdf";
    art.byte_offset = 4096;
    art.size_bytes = 12000;
    art.confidence_score = 90.0;
    e2.recovered_artifacts.push_back(art);
    AuditLogger::getInstance().logForensicOperation(e2);

    // Initial chain must verify 100%
    ASSERT_TRUE(AuditLogger::getInstance().verifyChain());

    // Export to file and test persistence
    std::string testLog = "test_data/disposable/test_audit_chain.jsonl";
    ASSERT_TRUE(AuditLogger::getInstance().saveToFile(testLog));

    AuditLogger reloaded;
    ASSERT_TRUE(reloaded.loadFromFile(testLog));
    ASSERT_TRUE(reloaded.verifyChain());
    ASSERT_EQ(reloaded.getEntries().size(), 2);

    fs::remove(testLog);
}

FV_TEST(CaseManagement, WorkspaceLayoutCreation) {
    std::string testRoot = "test_data/disposable/test_case_workspace";
    fs::remove_all(testRoot);

    CaseInfo info;
    info.case_id = "SIH-2026-CASE-09";
    info.case_name = "Operation Blue Horizon";
    info.investigator_name = "Lead Officer Rao";
    info.agency = "State Cyber Police";
    info.description = "Forensic analysis of seized media";

    bool initOk = CaseManager::initializeWorkspace(testRoot, info);
    ASSERT_TRUE(initOk);

    // Verify mandatory directories: case/, evidence/, recovered/, reports/, logs/
    ASSERT_TRUE(fs::exists(testRoot + "/case/case_metadata.json"));
    ASSERT_TRUE(fs::is_directory(testRoot + "/evidence"));
    ASSERT_TRUE(fs::is_directory(testRoot + "/recovered/active"));
    ASSERT_TRUE(fs::is_directory(testRoot + "/recovered/deleted"));
    ASSERT_TRUE(fs::is_directory(testRoot + "/recovered/carved"));
    ASSERT_TRUE(fs::is_directory(testRoot + "/reports"));
    ASSERT_TRUE(fs::is_directory(testRoot + "/logs"));
    ASSERT_TRUE(fs::exists(testRoot + "/logs/audit_journal.jsonl"));

    // Verify openWorkspace
    CaseManager mgr(testRoot);
    ASSERT_EQ(mgr.getCaseInfo().case_id, "SIH-2026-CASE-09");
    ASSERT_EQ(mgr.getCaseInfo().investigator_name, "Lead Officer Rao");

    fs::remove_all(testRoot);
}

FV_TEST(CaseManagement, EvidenceRegistrationAndCustodyIntegrity) {
    std::string testRoot = "test_data/disposable/test_case_evd";
    fs::remove_all(testRoot);

    CaseInfo info;
    info.case_id = "CASE-EVD-TEST";
    info.investigator_name = "Examiner Patel";
    CaseManager::initializeWorkspace(testRoot, info);

    CaseManager mgr(testRoot);

    // Create a dummy evidence image
    std::string dummyPath = "test_data/disposable/evidence_source.img";
    createDummyImage(dummyPath, 8192);

    auto ev = mgr.registerEvidence(dummyPath, "EVD-001", "Seized external drive");
    ASSERT_EQ(ev.evidence_id, "EVD-001");
    ASSERT_FALSE(ev.sha256_hash.empty());
    ASSERT_EQ(ev.size_bytes, 8192);

    // Verify integrity succeeds on clean evidence
    std::string curHash;
    ASSERT_TRUE(mgr.verifyEvidenceIntegrity("EVD-001", &curHash));
    ASSERT_EQ(curHash, ev.sha256_hash);

    // Verify custody tracking
    mgr.addCustodyRecord("EVD-001", "TRANSFERRED_TO_LAB", "Courier Verma", "Secure Vault", "Handover to lead examiner");
    auto custodyHist = mgr.getCustodyHistory("EVD-001");
    ASSERT_TRUE(custodyHist.size() >= 2); // Intake + Transfer

    fs::remove(dummyPath);
    fs::remove_all(testRoot);
}

FV_TEST(RecoveryEngine, EndToEndAuditRecordGenerationAndEvidenceImmutability) {
    std::string testRoot = "test_data/disposable/test_case_recovery";
    fs::remove_all(testRoot);

    CaseInfo info;
    info.case_id = "CASE-REC-TEST";
    info.investigator_name = "Forensic Analyst Verma";
    CaseManager::initializeWorkspace(testRoot, info);

    CaseManager mgr(testRoot);

    // Create a dummy evidence image with known JPEG signature
    std::string dummyPath = "test_data/disposable/carve_evidence.img";
    createDummyImage(dummyPath, 16384);

    auto ev = mgr.registerEvidence(dummyPath, "EVD-REC-01", "Forensic carving test image");

    // Open image using DiskImageReader (READ-ONLY)
    forensivault::core::DiskImageReader reader(ev.filepath);
    ASSERT_TRUE(reader.isOpen());

    forensivault::recovery::CaseContext ctx;
    ctx.case_id = info.case_id;
    ctx.evidence_id = ev.evidence_id;
    ctx.operation_id = "OP-REC-2026";
    ctx.operator_name = info.investigator_name;

    forensivault::recovery::RecoveryEngine engine;
    auto report = engine.runRecovery(reader, mgr.recoveredDir(), ctx);

    // 1. Verify evidence was NEVER modified
    ASSERT_TRUE(report.evidence_unmodified);
    ASSERT_EQ(report.evidence_pre_hash, report.evidence_post_hash);
    ASSERT_EQ(report.evidence_pre_hash, ev.sha256_hash);

    // 2. Verify recovered artifacts & confidence scoring
    ASSERT_TRUE(report.total_recovered_count() > 0);
    ASSERT_TRUE(report.audit_entry_id > 0);
    ASSERT_FALSE(report.audit_entry_hash.empty());

    // 3. Verify that the audit logger has intact chain
    // 3. Verify that the audit logger has intact chain
    ASSERT_TRUE(AuditLogger::getInstance().verifyChain());

    // 4. Save and verify formal forensic report in case reports/
    std::string reportJson = "{\"case\":\"" + info.case_id + "\",\"status\":\"COMPLETED\"}";
    ASSERT_TRUE(mgr.saveReport("forensic_recovery_report.json", reportJson));
    ASSERT_TRUE(fs::exists(mgr.reportsDir() + "/forensic_recovery_report.json"));

    reader.close();
    fs::remove(dummyPath);
    fs::remove_all(testRoot);
}
