#include "test_framework.hpp"
#include "core/user_auth_db.hpp"
#include "forensivault/common/crypto_hash.hpp"
#include "forensivault/core/platform.hpp"
#include "logging/audit_logger.hpp"
#include "reporting/report_generator.hpp"
#include "reporting/forensic_report.hpp"

#include <filesystem>
#include <fstream>

#if !defined(_WIN32)
#include <sys/stat.h>
#endif

namespace fs = std::filesystem;
using namespace forensivault;
using namespace forensivault::core;
using namespace forensivault::logging;
using namespace forensivault::reporting;

FV_TEST(UserAuthDB, PasswordComplexityValidation) {
    std::string reason;

    // Too short (< 8 chars)
    ASSERT_FALSE(UserAuthDB::validatePasswordComplexity("Sh0rt!", &reason));
    ASSERT_FALSE(reason.empty());

    // Missing uppercase
    ASSERT_FALSE(UserAuthDB::validatePasswordComplexity("nouppercase123!", &reason));

    // Missing lowercase
    ASSERT_FALSE(UserAuthDB::validatePasswordComplexity("NOLOWERCASE123!", &reason));

    // Missing digit
    ASSERT_FALSE(UserAuthDB::validatePasswordComplexity("NoDigitsHere!!", &reason));

    // Missing special character
    ASSERT_FALSE(UserAuthDB::validatePasswordComplexity("NoSpecialChar123", &reason));

    // Valid strong password
    ASSERT_TRUE(UserAuthDB::validatePasswordComplexity("Forensic#Secure2026", &reason));
}

FV_TEST(UserAuthDB, EnrollmentAndAuthentication) {
    std::string testDbPath = "test_data/disposable/test_users.db";
    std::error_code ec;
    fs::remove(testDbPath, ec);

    UserAuthDB db(testDbPath);
    ASSERT_FALSE(db.hasUsers());
    ASSERT_EQ(db.userCount(), 0);

    // Register primary administrator examiner
    std::string regErr;
    ASSERT_TRUE(db.registerUser("lead_examiner", "Forensic#Examiner2026", "Lead Forensic Examiner", &regErr));
    ASSERT_TRUE(db.hasUsers());
    ASSERT_EQ(db.userCount(), 1);
    ASSERT_TRUE(db.userExists("lead_examiner"));

    // Reject duplicate username
    ASSERT_FALSE(db.registerUser("lead_examiner", "Another#Pass2026", "Investigator", &regErr));

    // Successful authentication
    auto authOk = db.authenticate("lead_examiner", "Forensic#Examiner2026");
    ASSERT_EQ(static_cast<int>(authOk.status), static_cast<int>(AuthStatus::SUCCESS));
    ASSERT_EQ(authOk.user.username, "lead_examiner");
    ASSERT_EQ(authOk.user.role, "Lead Forensic Examiner");

    // Invalid password
    auto authBadPass = db.authenticate("lead_examiner", "WrongPassword!123");
    ASSERT_EQ(static_cast<int>(authBadPass.status), static_cast<int>(AuthStatus::INVALID_CREDENTIALS));

    // Nonexistent user
    auto authBadUser = db.authenticate("ghost_user", "AnyPassword!123");
    ASSERT_EQ(static_cast<int>(authBadUser.status), static_cast<int>(AuthStatus::USER_NOT_FOUND));

    // Reload from disk and verify persistence
    UserAuthDB reloadedDb(testDbPath);
    ASSERT_TRUE(reloadedDb.hasUsers());
    ASSERT_EQ(reloadedDb.userCount(), 1);
    auto authReloaded = reloadedDb.authenticate("lead_examiner", "Forensic#Examiner2026");
    ASSERT_EQ(static_cast<int>(authReloaded.status), static_cast<int>(AuthStatus::SUCCESS));

    fs::remove(testDbPath, ec);
}

FV_TEST(UserAuthDB, BruteForceRateLimitingLockout) {
    std::string testDbPath = "test_data/disposable/test_lockout_users.db";
    std::error_code ec;
    fs::remove(testDbPath, ec);

    UserAuthDB db(testDbPath);
    ASSERT_TRUE(db.registerUser("analyst1", "Analyst#Secret99", "Forensic Investigator"));

    // Attempt 1-4: Invalid credentials
    for (int i = 1; i <= 4; ++i) {
        auto res = db.authenticate("analyst1", "WrongAttempt" + std::to_string(i) + "!");
        ASSERT_EQ(static_cast<int>(res.status), static_cast<int>(AuthStatus::INVALID_CREDENTIALS));
    }

    // 5th attempt triggers account lockout
    auto res5 = db.authenticate("analyst1", "WrongAttempt5!");
    ASSERT_EQ(static_cast<int>(res5.status), static_cast<int>(AuthStatus::ACCOUNT_LOCKED));
    ASSERT_TRUE(res5.lockRemainingSeconds > 0);

    // Subsequent authentication even with CORRECT password is blocked while locked
    auto resLocked = db.authenticate("analyst1", "Analyst#Secret99");
    ASSERT_EQ(static_cast<int>(resLocked.status), static_cast<int>(AuthStatus::ACCOUNT_LOCKED));

    fs::remove(testDbPath, ec);
}

FV_TEST(UserAuthDB, FileSecurityAndLocation) {
    std::string defaultPath = UserAuthDB::getDefaultDbPath();
    ASSERT_FALSE(defaultPath.empty());

    // Path must NOT be inside the project workspace directory
    std::string currentDir = fs::current_path().string();
    ASSERT_TRUE(defaultPath.find(currentDir) == std::string::npos);

    // Path must be located inside the forensicvault config directory
    std::string configDir = Platform::getConfigDirectory();
    ASSERT_TRUE(defaultPath.find(configDir) != std::string::npos);

#if !defined(_WIN32)
    std::string testDbPath = "test_data/disposable/test_perms_user.db";
    std::error_code ec;
    fs::remove(testDbPath, ec);

    UserAuthDB db(testDbPath);
    ASSERT_TRUE(db.registerUser("sec_user", "SecUser#Pass2026", "Security Auditor"));

    struct stat st{};
    ASSERT_EQ(::stat(testDbPath.c_str(), &st), 0);
    // Owner read/write: 0600 (no group or other access)
    mode_t perms = st.st_mode & 0777;
    ASSERT_EQ(perms, static_cast<mode_t>(S_IRUSR | S_IWUSR));

    fs::remove(testDbPath, ec);
#endif
}

FV_TEST(AuditLogging, TextLogFormatAndReload) {
    std::string testLogPath = "test_data/disposable/test_audit.txt";
    std::error_code ec;
    fs::remove(testLogPath, ec);

    AuditLogger logger;
    logger.clear();

    logging::AuditEntry e1;
    e1.operation_type = "DISK_IMAGE_ACQUISITION";
    e1.operator_name = "Lead Investigator";
    e1.status = "SUCCESS";
    e1.source_identifier = "/dev/sdb";
    e1.details = "Bit-stream raw forensic image captured.";
    logger.logForensicOperation(e1);

    logging::AuditEntry e2;
    e2.operation_type = "PARTITION_TABLE_PARSE";
    e2.operator_name = "Lead Investigator";
    e2.status = "SUCCESS";
    e2.source_identifier = "/evidence/case_01.raw";
    e2.details = "GPT table decoded, 3 partitions found.";
    logger.logForensicOperation(e2);

    ASSERT_TRUE(logger.verifyChain());
    ASSERT_TRUE(logger.saveToTextFile(testLogPath));
    ASSERT_TRUE(fs::exists(testLogPath));
    ASSERT_TRUE(fs::file_size(testLogPath) > 0);

    // Reload from plain text and verify unbroken SHA-256 chain
    AuditLogger reloaded;
    ASSERT_TRUE(reloaded.loadFromFile(testLogPath));
    ASSERT_TRUE(reloaded.verifyChain());
    ASSERT_EQ(reloaded.getEntries().size(), 2);

    fs::remove(testLogPath, ec);
}

FV_TEST(Reporting, DirectVectorPdfGeneration) {
    std::string testPdfPath = "test_data/disposable/test_direct.pdf";
    std::error_code ec;
    fs::remove(testPdfPath, ec);

    ForensicReport rep;
    rep.report_id = "TEST-PDF-001";
    rep.report_timestamp_iso = "2026-09-28T12:00:00Z";
    rep.case_info.case_id = "CASE-NATIVE-PDF";
    rep.case_info.case_name = "Native Vector PDF Engine Validation";
    rep.case_info.investigator_name = "Lead Examiner";
    rep.case_info.agency = "Digital Forensics Unit";
    rep.acquisition.source_path = "/evidence/disk.img";
    rep.acquisition.total_bytes = 104857600;
    rep.acquisition.total_sectors = 204800;
    rep.acquisition.sector_size = 512;
    rep.acquisition.intake_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    rep.evidence_pre_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    rep.evidence_post_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    rep.evidence_unmodified = true;

    ReportItem it1;
    it1.item_id = 1;
    it1.filename = "secret_ledger.xlsx";
    it1.size_bytes = 45200;
    it1.file_type = "XLSX";
    it1.confidence_level = "High";
    it1.sha256_hash = "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00";
    rep.recovered_items.push_back(it1);

    logging::AuditEntry a1;
    a1.entry_id = 1;
    a1.timestamp_iso = "2026-09-28T12:05:00Z";
    a1.operation_type = "CARVE_EXECUTION";
    a1.operator_name = "Lead Examiner";
    a1.status = "SUCCESS";
    a1.entry_hash = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
    rep.audit_trail.push_back(a1);

    ASSERT_TRUE(ReportGenerator::generatePdfDirect(rep, testPdfPath));
    ASSERT_TRUE(fs::exists(testPdfPath));
    ASSERT_TRUE(fs::file_size(testPdfPath) > 500);

    // Verify PDF 1.4 header and trailer in file
    std::ifstream pdfIfs(testPdfPath, std::ios::binary);
    std::string header(8, '\0');
    pdfIfs.read(&header[0], 8);
    ASSERT_TRUE(header.find("%PDF-1.4") != std::string::npos);

    pdfIfs.seekg(-16, std::ios::end);
    std::string trailer(16, '\0');
    pdfIfs.read(&trailer[0], 16);
    ASSERT_TRUE(trailer.find("%%EOF") != std::string::npos);

    fs::remove(testPdfPath, ec);
}
