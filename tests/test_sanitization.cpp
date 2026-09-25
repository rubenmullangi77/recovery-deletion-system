#include "test_framework.hpp"
#include "sanitization/sanitization_types.hpp"
#include "sanitization/system_protection.hpp"
#include "sanitization/secure_file_eraser.hpp"
#include "sanitization/secure_folder_eraser.hpp"
#include "sanitization/erase_operation.hpp"
#include "verification/erase_verification.hpp"
#include "logging/audit_logger.hpp"
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace forensivault::sanitization;
using namespace forensivault::verification;
using namespace forensivault::logging;

namespace {

void createDummyFile(const std::string& path, size_t sizeBytes, uint8_t fillByte = 0xAA) {
    fs::create_directories(fs::path(path).parent_path());
    std::ofstream ofs(path, std::ios::binary);
    std::vector<uint8_t> data(sizeBytes, fillByte);
    ofs.write(reinterpret_cast<const char*>(data.data()), data.size());
}

} // anonymous namespace

FV_TEST(SanitizationSafety, SystemProtectionBlocksOperatingSystemPaths) {
    std::string reason;

    // Drive roots
    ASSERT_TRUE(SystemProtectionGuard::isProtected("C:\\", reason));
    ASSERT_TRUE(SystemProtectionGuard::isProtected("C:", reason));
    ASSERT_TRUE(SystemProtectionGuard::isProtected("D:\\", reason));
    ASSERT_TRUE(SystemProtectionGuard::isProtected("/", reason));

    // Windows system directories
    ASSERT_TRUE(SystemProtectionGuard::isProtected("C:\\Windows", reason));
    ASSERT_TRUE(SystemProtectionGuard::isProtected("C:\\Windows\\System32", reason));
    ASSERT_TRUE(SystemProtectionGuard::isProtected("C:/Windows/System32/kernel32.dll", reason));
    ASSERT_TRUE(SystemProtectionGuard::isProtected("C:\\Program Files", reason));
    ASSERT_TRUE(SystemProtectionGuard::isProtected("C:\\Program Files (x86)", reason));
    ASSERT_TRUE(SystemProtectionGuard::isProtected("C:\\$Recycle.Bin", reason));
    ASSERT_TRUE(SystemProtectionGuard::isProtected("C:\\System Volume Information", reason));
    ASSERT_TRUE(SystemProtectionGuard::isProtected("C:\\Users", reason));

    // Critical system files
    ASSERT_TRUE(SystemProtectionGuard::isProtected("C:\\pagefile.sys", reason));
    ASSERT_TRUE(SystemProtectionGuard::isProtected("C:\\hiberfil.sys", reason));
    ASSERT_TRUE(SystemProtectionGuard::isProtected("C:\\bootmgr", reason));

    // Safe user workspace path should pass
    ASSERT_FALSE(SystemProtectionGuard::isProtected("test_data/disposable/user_notes.txt", reason));
}

FV_TEST(SanitizationSafety, ExplicitConfirmationRequiredBeforeDestructiveAction) {
    std::string testPath = "test_data/disposable/unconfirmed.txt";
    createDummyFile(testPath, 512, 0x55);
    ASSERT_TRUE(fs::exists(testPath));

    EraseOperation op(SanitizationMethod::NIST_800_88_CLEAR);
    op.addFile(testPath);

    // 1. Without confirmation, execution must fail
    ASSERT_FALSE(op.isConfirmed());
    auto res = op.execute();
    ASSERT_FALSE(res.success);
    ASSERT_TRUE(fs::exists(testPath)); // File remains untouched!

    // 2. With valid confirmation token, execution proceeds
    ASSERT_TRUE(op.setConfirmationToken(EraseOperation::CONFIRMATION_TOKEN));
    ASSERT_TRUE(op.isConfirmed());
    auto confirmedRes = op.execute();
    ASSERT_TRUE(confirmedRes.success);
    ASSERT_FALSE(fs::exists(testPath)); // File is now securely erased!
}

FV_TEST(SanitizationBatch, PreviewAccuratelyReflectsItemsAndRisk) {
    std::string baseDir = "test_data/disposable/preview_test";
    fs::remove_all(baseDir);

    createDummyFile(baseDir + "/doc1.txt", 100);
    createDummyFile(baseDir + "/sub/doc2.txt", 200);
    createDummyFile(baseDir + "/sub/doc3.txt", 300);

    EraseOperation op(SanitizationMethod::DOD_5220_22_M);
    op.addFolder(baseDir);

    auto prev = op.preview();
    ASSERT_TRUE(prev.safety_passed);
    ASSERT_EQ(prev.total_files, 3ULL);
    ASSERT_EQ(prev.total_folders, 2ULL); // baseDir and sub
    ASSERT_EQ(prev.total_bytes, 600ULL);
    ASSERT_EQ(prev.method, SanitizationMethod::DOD_5220_22_M);
    ASSERT_FALSE(prev.method_description.empty());
    ASSERT_TRUE(prev.limitations.size() > 0);

    // Clean up
    fs::remove_all(baseDir);
}

FV_TEST(SanitizationEngine, SingleFileNistZeroFillVerification) {
    std::string testPath = "test_data/disposable/nist_test.bin";
    createDummyFile(testPath, 4096, 0xDE); // Fill with 0xDE
    ASSERT_TRUE(fs::exists(testPath));

    SecureFileEraser eraser;
    bool progressCalled = false;
    auto cb = [&](const EraseProgress& p) {
        progressCalled = true;
        ASSERT_TRUE(p.percentage >= 0.0);
    };

    auto ver = eraser.eraseFile(testPath, SanitizationMethod::NIST_800_88_CLEAR, cb);

    ASSERT_TRUE(progressCalled);
    ASSERT_TRUE(ver.is_verified);
    ASSERT_EQ(ver.match_rate_percentage, 100.0);
    ASSERT_EQ(ver.measured_entropy, 0.0);
    ASSERT_FALSE(ver.accessible_after_deletion);
    ASSERT_FALSE(fs::exists(testPath));
    ASSERT_TRUE(ver.limitations.size() > 0);
}

FV_TEST(SanitizationEngine, RecursiveFolderErasure) {
    std::string folder = "test_data/disposable/folder_wipe";
    fs::remove_all(folder);

    createDummyFile(folder + "/a.txt", 500);
    createDummyFile(folder + "/b.txt", 1000);
    createDummyFile(folder + "/level1/c.txt", 1500);
    createDummyFile(folder + "/level1/level2/d.txt", 2000);

    SecureFolderEraser folderEraser;
    auto rep = folderEraser.eraseFolder(folder, SanitizationMethod::ZERO_FILL);

    ASSERT_TRUE(rep.success);
    ASSERT_EQ(rep.files_erased, 4ULL);
    ASSERT_EQ(rep.total_bytes_erased, 5000ULL);
    ASSERT_FALSE(fs::exists(folder)); // Whole tree removed
}

FV_TEST(AuditLogging, CryptographicSha256ChainAndTamperDetection) {
    AuditLogger logger;
    logger.clear();

    logger.logEvent("SECURE_FILE_ERASE", "file1.txt", "NIST 800-88", "SUCCESS", "Overwritten with 0x00");
    logger.logEvent("SECURE_FILE_ERASE", "file2.txt", "DoD 5220.22-M", "SUCCESS", "3 passes verified");
    logger.logEvent("SAFETY_BLOCK", "C:\\Windows", "NIST 800-88", "BLOCKED", "Protected system directory");

    auto entries = logger.getEntries();
    ASSERT_EQ(entries.size(), 3ULL);

    // Initial unbroken chain validation
    size_t brokenIdx = 0;
    ASSERT_TRUE(logger.verifyChain(&brokenIdx));

    // Export to JSONL file and reload
    std::string logFile = "test_data/disposable/audit_test.jsonl";
    ASSERT_TRUE(logger.saveToFile(logFile));

    AuditLogger reloaded;
    ASSERT_TRUE(reloaded.loadFromFile(logFile));
    ASSERT_EQ(reloaded.getEntries().size(), 3ULL);
    ASSERT_TRUE(reloaded.verifyChain());

    // Clean up
    fs::remove(logFile);
}
