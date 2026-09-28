#include "test_framework.hpp"
#include "forensivault/directory_recovery.hpp"
#include "forensivault/file_eraser.hpp"
#include "forensivault/common/crypto_hash.hpp"
#include "recovery/directory_scanner.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

namespace fs = std::filesystem;
using namespace forensivault;
using namespace forensivault::api;

FV_TEST(DirectoryRecovery, UrlDecode) {
    ASSERT_EQ(recovery::DirectoryScanner::urlDecode("hello%20world"), "hello world");
    ASSERT_EQ(recovery::DirectoryScanner::urlDecode("/path/to/my%20file.txt"), "/path/to/my file.txt");
    ASSERT_EQ(recovery::DirectoryScanner::urlDecode("no_encoding_here"), "no_encoding_here");
    ASSERT_EQ(recovery::DirectoryScanner::urlDecode("percent%25symbol"), "percent%symbol");
}

FV_TEST(DirectoryRecovery, ResolveMountInfo) {
    std::string testPath = fs::current_path().string();
    auto info = DirectoryRecoveryAPI::inspectDirectory(testPath);

    ASSERT_TRUE(!info.directoryPath.empty());
    ASSERT_TRUE(!info.mountPoint.empty());
    ASSERT_TRUE(!info.filesystemType.empty());
    ASSERT_TRUE(info.totalBytes > 0ULL);
}

FV_TEST(DirectoryRecovery, SafetyInterlockBlocksOutputInsideScanned) {
    std::string testDir = "/tmp/fv_safety_test";
    std::error_code ec;
    fs::create_directories(testDir, ec);

    std::vector<DiscoveredDeletedItem> items;
    DiscoveredDeletedItem item;
    item.filename = "dummy.txt";
    item.originalPath = testDir + "/dummy.txt";
    items.push_back(item);

    // 1. Output is same directory
    auto res1 = DirectoryRecoveryAPI::recoverItems(testDir, items, testDir);
    ASSERT_FALSE(res1.success);
    ASSERT_TRUE(res1.errorMessage.find("Safety Violation") != std::string::npos);

    // 2. Output is subfolder of scanned directory
    auto res2 = DirectoryRecoveryAPI::recoverItems(testDir, items, testDir + "/recovered_sub");
    ASSERT_FALSE(res2.success);
    ASSERT_TRUE(res2.errorMessage.find("Safety Violation") != std::string::npos);

    fs::remove_all(testDir, ec);
}

FV_TEST(DirectoryRecovery, EndToEndSyntheticTrashScanAndRecovery) {
    fs::path baseDir = "/tmp/fv_synthetic_trash_test";
    std::error_code ec;
    fs::remove_all(baseDir, ec);

    fs::path workDir = baseDir / "my_work";
    fs::path trashDir = workDir / ".Trash";
    fs::path infoDir = trashDir / "info";
    fs::path filesDir = trashDir / "files";
    fs::path outDir = baseDir / "restored_evidence";

    fs::create_directories(infoDir, ec);
    fs::create_directories(filesDir, ec);
    fs::create_directories(outDir, ec);

    // 1. Create a deleted file payload and its .trashinfo entry
    std::string fileContent = "ForensiVault High-Fidelity Deleted File Recovery Test";
    std::string expectedSha = CryptoHash::sha256(reinterpret_cast<const uint8_t*>(fileContent.data()), fileContent.size());
    
    fs::path payloadFile = filesDir / "important_document.pdf";
    {
        std::ofstream ofs(payloadFile, std::ios::binary);
        ofs.write(fileContent.data(), fileContent.size());
    }

    fs::path trashInfoFile = infoDir / "important_document.pdf.trashinfo";
    {
        std::ofstream ofs(trashInfoFile);
        ofs << "[Trash Info]\n";
        ofs << "Path=" << (workDir / "important_document.pdf").string() << "\n";
        ofs << "DeletionDate=2026-09-28T11:00:00\n";
    }

    // 2. Scan the work directory
    auto scanRes = DirectoryRecoveryAPI::scanDirectory(workDir.string());
    ASSERT_TRUE(scanRes.success);
    ASSERT_TRUE(scanRes.items.size() >= 1ULL);

    bool found = false;
    DiscoveredDeletedItem recoveredCandidate;
    for (const auto& item : scanRes.items) {
        if (item.filename == "important_document.pdf") {
            found = true;
            recoveredCandidate = item;
            ASSERT_EQ(item.extension, "pdf");
            ASSERT_EQ(item.sizeBytes, fileContent.size());
            ASSERT_EQ(item.confidenceScore, 100);
            ASSERT_TRUE(item.source == DetectionSource::TRASH_JOURNAL);
            break;
        }
    }
    ASSERT_TRUE(found);

    // 3. Execute recovery
    std::vector<DiscoveredDeletedItem> toRecover = { recoveredCandidate };
    auto recRes = DirectoryRecoveryAPI::recoverItems(workDir.string(), toRecover, outDir.string());
    ASSERT_TRUE(recRes.success);
    ASSERT_EQ(recRes.recoveredCount, 1ULL);
    ASSERT_EQ(recRes.recoveredBytes, fileContent.size());

    // 4. Verify restored file
    fs::path restoredFile = outDir / "important_document.pdf";
    ASSERT_TRUE(fs::exists(restoredFile, ec));
    
    std::ifstream ifs(restoredFile, std::ios::binary);
    std::string restoredContent((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    ASSERT_EQ(restoredContent, fileContent);
    ASSERT_EQ(CryptoHash::sha256(reinterpret_cast<const uint8_t*>(restoredContent.data()), restoredContent.size()), expectedSha);

    // Clean up
    fs::remove_all(baseDir, ec);
}

FV_TEST(DirectoryRecovery, SanitizedAuditRecordsDiscoveredAndIrrecoverable) {
    fs::path baseDir = "test_data/disposable/audit_recovery_test";
    std::error_code ec;
    fs::remove_all(baseDir, ec);
    fs::create_directories(baseDir, ec);

    fs::path targetFile = baseDir / "secret_finance.xlsx";
    {
        std::ofstream ofs(targetFile, std::ios::binary);
        ofs << "Confidential corporate payroll data 2026";
    }

    // 1. Erase file using FileEraserAPI (NIST SP 800-88 Clear)
    auto eraseRes = FileEraserAPI::eraseFile(targetFile.string(), EraseMethod::NIST_800_88_CLEAR);
    ASSERT_TRUE(eraseRes.success);
    ASSERT_FALSE(fs::exists(targetFile, ec));

    // 2. Scan directory for deleted items
    auto scanRes = DirectoryRecoveryAPI::scanDirectory(baseDir.string());
    ASSERT_TRUE(scanRes.success);

    // Verify sanitized item appears in scan results
    bool foundSanitized = false;
    DiscoveredDeletedItem sanitizedItem;
    for (const auto& item : scanRes.items) {
        if (item.filename == "secret_finance.xlsx") {
            foundSanitized = true;
            sanitizedItem = item;
            ASSERT_TRUE(item.source == DetectionSource::SANITIZED_AUDIT);
            ASSERT_EQ(item.confidenceScore, 0);
            ASSERT_EQ(item.confidenceLevel, "Irrecoverable");
            break;
        }
    }
    ASSERT_TRUE(foundSanitized);

    // 3. Attempting recovery on sanitized item must fail safely
    fs::path outDir = "test_data/disposable/audit_recovery_out";
    fs::remove_all(outDir, ec);
    fs::create_directories(outDir, ec);

    std::vector<DiscoveredDeletedItem> itemsToRecover = { sanitizedItem };
    auto recRes = DirectoryRecoveryAPI::recoverItems(baseDir.string(), itemsToRecover, outDir.string());
    ASSERT_EQ(recRes.recoveredCount, 0ULL);
    ASSERT_FALSE(recRes.errors.empty());

    // Clean up
    fs::remove_all(baseDir, ec);
    fs::remove_all(outDir, ec);
}

FV_TEST(DirectoryRecovery, SmallFilesFolderErasureCalculatesAccurateSize) {
    fs::path folder = "test_data/disposable/small_folder_erase";
    std::error_code ec;
    fs::remove_all(folder, ec);
    fs::create_directories(folder, ec);

    // Create 3 small files (< 100 bytes each)
    {
        std::ofstream ofs(folder / "note1.txt");
        ofs << "Short note 1"; // 12 bytes
    }
    {
        std::ofstream ofs(folder / "note2.txt");
        ofs << "Short note number 2 with some more text"; // 39 bytes
    }
    {
        std::ofstream ofs(folder / "sub" / "note3.txt");
        fs::create_directories(folder / "sub", ec);
        ofs.open(folder / "sub" / "note3.txt");
        ofs << "Sub-folder text payload"; // 23 bytes
    }

    // 1. Preview
    auto prev = FileEraserAPI::preview(folder.string());
    ASSERT_EQ(prev.totalFiles, 3ULL);
    ASSERT_TRUE(prev.totalBytes >= 74ULL);

    // 2. Erase with DoD 5220.22-M 3-pass (which requires entropy scaling for small buffers)
    auto eraseRes = FileEraserAPI::eraseDirectory(folder.string(), EraseMethod::DOD_5220_22_M);
    ASSERT_TRUE(eraseRes.success);
    ASSERT_EQ(eraseRes.filesErased, 3ULL);
    ASSERT_TRUE(eraseRes.bytesErased >= 74ULL);
    ASSERT_FALSE(fs::exists(folder, ec));

    // Clean up
    fs::remove_all(folder, ec);
}
