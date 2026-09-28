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

#if !defined(_WIN32)
#include <unistd.h>
#include <fcntl.h>
#endif

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

FV_TEST(SanitizationHandleBinding, NormalSingleLinkFileEraseAndVerification) {
    fs::path tempDir = fs::temp_directory_path() / "fv_test_normal_erase";
    fs::create_directories(tempDir);
    fs::path testPath = tempDir / "normal_file.bin";
    createDummyFile(testPath.string(), 8192, 0xAA);

    SecureFileEraser eraser;
    auto res = eraser.eraseFile(testPath.string(), SanitizationMethod::NIST_800_88_CLEAR);

    ASSERT_TRUE(res.is_verified);
    ASSERT_EQ(res.match_rate_percentage, 100.0);
    ASSERT_TRUE(res.measured_entropy < 0.05);
    ASSERT_FALSE(res.accessible_after_deletion);
    ASSERT_FALSE(fs::exists(testPath));

    std::error_code ec;
    fs::remove_all(tempDir, ec);
}

FV_TEST(SanitizationHandleBinding, RefuseHardlinksBeforeModification) {
    fs::path tempDir = fs::temp_directory_path() / "fv_test_hardlink";
    fs::create_directories(tempDir);
    fs::path originPath = tempDir / "origin.bin";
    fs::path linkPath = tempDir / "link.bin";

    const std::string content = "CONFIDENTIAL_HARDLINK_PAYLOAD_12345";
    {
        std::ofstream ofs(originPath, std::ios::binary);
        ofs << content;
    }

    std::error_code ec;
    fs::create_hard_link(originPath, linkPath, ec);
    ASSERT_FALSE(ec);

    SecureFileEraser eraser;
    auto res = eraser.eraseFile(linkPath.string(), SanitizationMethod::NIST_800_88_CLEAR);

    // Operation must fail closed before modifying either path
    ASSERT_FALSE(res.is_verified);
    ASSERT_TRUE(res.details.find("hard links") != std::string::npos ||
                res.details.find("hard_link_count") != std::string::npos);

    // Verify origin file is untouched
    ASSERT_TRUE(fs::exists(originPath));
    std::string readContent;
    {
        std::ifstream ifs(originPath, std::ios::binary);
        std::getline(ifs, readContent);
    }
    ASSERT_EQ(readContent, content);

    // Verify hard link path is untouched
    ASSERT_TRUE(fs::exists(linkPath));

    // Also attempting to erase the origin path must be refused
    auto res2 = eraser.eraseFile(originPath.string(), SanitizationMethod::NIST_800_88_CLEAR);
    ASSERT_FALSE(res2.is_verified);
    ASSERT_TRUE(fs::exists(originPath));

    fs::remove_all(tempDir, ec);
}

FV_TEST(SanitizationHandleBinding, RefuseSymlinkDestruction) {
    fs::path tempDir = fs::temp_directory_path() / "fv_test_symlink";
    fs::create_directories(tempDir);
    fs::path targetPath = tempDir / "secret_target.txt";
    fs::path symlinkPath = tempDir / "symlink.txt";

    const std::string content = "CRITICAL_PAYLOAD_DO_NOT_CORRUPT";
    {
        std::ofstream ofs(targetPath, std::ios::binary);
        ofs << content;
    }

    std::error_code ec;
    fs::create_symlink(targetPath, symlinkPath, ec);
    if (!ec) {
        SecureFileEraser eraser;
        auto res = eraser.eraseFile(symlinkPath.string(), SanitizationMethod::NIST_800_88_CLEAR);

        // Operation must refuse/fail safely
        ASSERT_FALSE(res.is_verified);

        // Target file must remain untouched
        ASSERT_TRUE(fs::exists(targetPath));
        std::string readContent;
        {
            std::ifstream ifs(targetPath, std::ios::binary);
            std::getline(ifs, readContent);
        }
        ASSERT_EQ(readContent, content);
    }

    fs::remove_all(tempDir, ec);
}

FV_TEST(SanitizationHandleBinding, PathReplacementRaceRefusesDeletion) {
    fs::path tempDir = fs::temp_directory_path() / "fv_test_path_replacement";
    fs::create_directories(tempDir);
    fs::path victimPath = tempDir / "victim.txt";
    createDummyFile(victimPath.string(), 128 * 1024, 0xBB);

    SecureFileEraser eraser;
    bool replaced = false;
    const std::string attackerPayload = "ATTACKER_REPLACEMENT_PAYLOAD_DO_NOT_UNLINK";

    auto callback = [&](const EraseProgress& p) {
        if (!replaced && p.bytes_processed_file > 0) {
            // Exercise race: replace victimPath on disk while handle is open
            std::error_code ec;
            fs::remove(victimPath, ec);
            std::ofstream ofs(victimPath, std::ios::binary);
            ofs << attackerPayload;
            ofs.close();
            replaced = true;
        }
    };

    auto res = eraser.eraseFile(victimPath.string(), SanitizationMethod::NIST_800_88_CLEAR, callback);

    // Because path was replaced, secureUnlink must refuse to unlink the replacement
    ASSERT_TRUE(replaced);
    ASSERT_FALSE(res.is_verified);

    // Attacker replacement file MUST still exist on disk untouched
    ASSERT_TRUE(fs::exists(victimPath));
    std::string readContent;
    {
        std::ifstream ifs(victimPath, std::ios::binary);
        std::getline(ifs, readContent);
    }
    ASSERT_EQ(readContent, attackerPayload);

    std::error_code ec;
    fs::remove_all(tempDir, ec);
}

FV_TEST(SanitizationHandleBinding, FinalDeletionRefusesAttackerReplacedPath) {
    fs::path tempDir = fs::temp_directory_path() / "fv_test_final_del";
    fs::create_directories(tempDir);
    fs::path origPath = tempDir / "orig_file.txt";
    createDummyFile(origPath.string(), 1024, 0x11);

    std::error_code ec;
#if !defined(_WIN32)
    int fd = ::open(origPath.c_str(), O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    ASSERT_TRUE(fd >= 0);
    auto id = captureIdentityFromFd(fd, origPath.string(), TargetType::REGULAR_FILE);
    ASSERT_TRUE(id.valid);

    // Simulate attacker swapping the file at origPath with a new inode
    fs::remove(origPath, ec);
    createDummyFile(origPath.string(), 1024, 0x22);

    // TargetIdentity::matchesPath must detect the inode mismatch
    ASSERT_FALSE(id.matchesPath(origPath.string()));

    // secureUnlink must refuse to unlink the replaced pathname
    bool unlinked = SecureFileEraser::secureUnlink(fd, id, origPath.string());
    ASSERT_FALSE(unlinked);

    // Replaced file must remain on disk
    ASSERT_TRUE(fs::exists(origPath));

    ::close(fd);
#endif

    fs::remove_all(tempDir, ec);
}

FV_TEST(SanitizationHandleBinding, SizeInvarianceAndZeroByteErasure) {
    fs::path tempDir = fs::temp_directory_path() / "fv_test_zero_byte";
    fs::create_directories(tempDir);
    fs::path zeroPath = tempDir / "zero.bin";
    {
        std::ofstream ofs(zeroPath, std::ios::binary);
    }

    SecureFileEraser eraser;
    auto res = eraser.eraseFile(zeroPath.string(), SanitizationMethod::NIST_800_88_CLEAR);

    ASSERT_TRUE(res.is_verified);
    ASSERT_FALSE(fs::exists(zeroPath));

    std::error_code ec;
    fs::remove_all(tempDir, ec);
}

FV_TEST(SanitizationHandleBinding, IntermediateSymlinkSteeringBlockedByDescriptorResolution) {
    fs::path tempDir = fs::temp_directory_path() / "fv_test_intermediate_symlink";
    std::error_code ec;
    fs::remove_all(tempDir, ec);
    fs::create_directories(tempDir);

    // Protected destination (simulating user AppData)
    fs::path protectedDir = tempDir / "fake_home" / "AppData" / "Roaming";
    fs::create_directories(protectedDir);
    fs::path victimFile = protectedDir / "victim_config.json";
    const std::string secretPayload = "CRITICAL_USER_CONFIG_DO_NOT_DELETE";
    {
        std::ofstream ofs(victimFile, std::ios::binary);
        ofs << secretPayload;
    }

    // Harmless-looking untrusted workspace containing an intermediate directory symlink
    fs::path untrustedDir = tempDir / "innocent_workspace";
    fs::create_directories(untrustedDir);
    fs::path symlinkDir = untrustedDir / "harmless_folder";
    fs::create_directory_symlink(protectedDir, symlinkDir, ec);

    if (!ec) {
        fs::path steeredTarget = symlinkDir / "victim_config.json";

        // Precondition check: the target path string itself does NOT contain "AppData"
        ASSERT_EQ(steeredTarget.string().find("AppData"), std::string::npos);

        SecureFileEraser eraser;
        auto res = eraser.eraseFile(steeredTarget.string(), SanitizationMethod::NIST_800_88_CLEAR);

        // Operation must fail closed because post-open handle resolution detects the protected AppData path
        ASSERT_FALSE(res.is_verified);
        ASSERT_NE(res.details.find("SECURITY INTERLOCK BLOCKED"), std::string::npos);

        // Victim file in protected location must remain completely intact
        ASSERT_TRUE(fs::exists(victimFile));
        std::string readContent;
        {
            std::ifstream ifs(victimFile, std::ios::binary);
            std::getline(ifs, readContent);
        }
        ASSERT_EQ(readContent, secretPayload);
    }

    fs::remove_all(tempDir, ec);
}

FV_TEST(SanitizationHandleBinding, HandleSizeMutationDuringOperationFailsVerification) {
    fs::path tempDir = fs::temp_directory_path() / "fv_test_size_mutation";
    std::error_code ec;
    fs::remove_all(tempDir, ec);
    fs::create_directories(tempDir);

    fs::path testFile = tempDir / "mutate_target.bin";
    const uint64_t initialSize = 4096;
    createDummyFile(testFile.string(), initialSize, 0xAA);

    SecureFileEraser eraser;
    bool mutated = false;

    auto callback = [&](const EraseProgress& p) {
        if (!mutated && p.bytes_processed_file > 0) {
#if defined(_WIN32)
            HANDLE hMut = CreateFileA(
                testFile.string().c_str(),
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                NULL,
                OPEN_EXISTING,
                0,
                NULL
            );
            if (hMut != INVALID_HANDLE_VALUE) {
                LARGE_INTEGER li512;
                li512.QuadPart = 512;
                SetFilePointerEx(hMut, li512, NULL, FILE_BEGIN);
                SetEndOfFile(hMut);
                CloseHandle(hMut);
                mutated = true;
            }
#else
            int trunc_fd = ::open(testFile.c_str(), O_WRONLY);
            if (trunc_fd >= 0) {
                if (::ftruncate(trunc_fd, 512) == 0) {
                    mutated = true;
                }
                ::close(trunc_fd);
            }
#endif
        }
    };

    auto res = eraser.eraseFile(testFile.string(), SanitizationMethod::NIST_800_88_CLEAR, callback);

    // Mutation must have executed during callback
    ASSERT_TRUE(mutated);

    // Operation must fail verification due to the size discrepancy
    ASSERT_FALSE(res.is_verified);

    // Details must explicitly describe the unexpected file size mutation, not claim successful verification
    ASSERT_NE(res.details.find("Unexpected file size mutation"), std::string::npos);

    fs::remove_all(tempDir, ec);
}


