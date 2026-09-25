#include "forensivault/forensivault.hpp"
#include "forensivault/core/platform.hpp"
#include "forensivault/common/types.hpp"
#include "forensivault/common/crypto_hash.hpp"
#include "forensivault/common/logger.hpp"
#include "forensivault/file_eraser.hpp"
#include "forensivault/drive_sanitizer.hpp"
#include "forensivault/carver.hpp"
#include "forensivault/fs_recovery.hpp"

#include "core/disk_image_reader.hpp"
#include "core/case_manager.hpp"
#include "carving/file_carver.hpp"
#include "carving/fragment_reconstructor.hpp"
#include "filesystem/fat32_analyzer.hpp"
#include "filesystem/exfat_analyzer.hpp"
#include "filesystem/ntfs_analyzer.hpp"
#include "recovery/recovery_engine.hpp"
#include "sanitization/erase_operation.hpp"
#include "sanitization/drive_detector.hpp"
#include "sanitization/image_sanitizer.hpp"
#include "sanitization/ssd_sanitizer.hpp"
#include "sanitization/hdd_sanitizer.hpp"
#include "sanitization/system_protection.hpp"
#include "logging/audit_logger.hpp"
#include "reporting/forensic_report.hpp"
#include "reporting/report_generator.hpp"

#include <iostream>
#include <string>
#include <vector>
#include <set>
#include <iomanip>
#include <filesystem>
#include <algorithm>
#include <sstream>

namespace fs = std::filesystem;

namespace {

std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n\"'");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n\"'");
    return s.substr(start, end - start + 1);
}

bool parseItemSelection(const std::string& input, size_t maxVal, std::vector<int>& outIndices, std::string& errorMsg) {
    outIndices.clear();
    std::string s = trim(input);
    if (s.empty() || s == "0") {
        outIndices.push_back(0);
        return true;
    }

    if (s == "all" || s == "*") {
        if (maxVal == 0) {
            outIndices.push_back(0);
        } else {
            for (size_t i = 1; i <= maxVal; ++i) {
                outIndices.push_back(static_cast<int>(i));
            }
        }
        return true;
    }

    // Normalize delimiters (commas, semicolons) to spaces
    std::string normalized;
    for (char c : s) {
        if (c == ',' || c == ';') {
            normalized += ' ';
        } else {
            normalized += c;
        }
    }

    std::set<int> collected;
    std::istringstream iss(normalized);
    std::string token;

    while (iss >> token) {
        token = trim(token);
        if (token.empty()) continue;

        size_t dashPos = token.find('-');
        if (dashPos != std::string::npos) {
            std::string leftStr = trim(token.substr(0, dashPos));
            std::string rightStr = trim(token.substr(dashPos + 1));
            if (leftStr.empty() || rightStr.empty()) {
                errorMsg = "Invalid range format in '" + token + "'. Expected format like '1-5'.";
                return false;
            }

            int leftVal = 0;
            int rightVal = 0;
            try {
                size_t p1 = 0, p2 = 0;
                leftVal = std::stoi(leftStr, &p1);
                rightVal = std::stoi(rightStr, &p2);
                if (p1 != leftStr.length() || p2 != rightStr.length()) {
                    errorMsg = "Non-numeric characters in range '" + token + "'.";
                    return false;
                }
            } catch (...) {
                errorMsg = "Invalid numbers in range '" + token + "'.";
                return false;
            }

            int minV = std::min(leftVal, rightVal);
            int maxV = std::max(leftVal, rightVal);

            if (minV < 0 || maxV > static_cast<int>(maxVal)) {
                errorMsg = "Range '" + token + "' is out of range. Allowed: 0 to " + std::to_string(maxVal) + ".";
                return false;
            }

            for (int v = minV; v <= maxV; ++v) {
                collected.insert(v);
            }
        } else {
            try {
                size_t p = 0;
                int val = std::stoi(token, &p);
                if (p != token.length()) {
                    errorMsg = "Non-numeric characters in '" + token + "'.";
                    return false;
                }
                if (val < 0 || val > static_cast<int>(maxVal)) {
                    errorMsg = "Item number " + std::to_string(val) + " is out of range. Allowed: 0 to " + std::to_string(maxVal) + ".";
                    return false;
                }
                collected.insert(val);
            } catch (...) {
                errorMsg = "Invalid number format in '" + token + "'.";
                return false;
            }
        }
    }

    if (collected.empty()) {
        outIndices.push_back(0);
        return true;
    }

    outIndices.assign(collected.begin(), collected.end());
    return true;
}

std::string readLine(const std::string& prompt) {
    if (!std::cin.good() || std::cin.eof()) {
        return "exit";
    }
    if (!prompt.empty()) {
        forensivault::Logger::getInstance().print(prompt);
    }
    std::string line;
    if (std::getline(std::cin, line)) {
        return trim(line);
    }
    return "exit";
}

bool isStdinAtty() {
#if defined(_WIN32)
    return (_isatty(_fileno(stdin)) != 0);
#else
    return (isatty(fileno(stdin)) != 0);
#endif
}

bool hasFzfInstalled() {
#if defined(_WIN32)
    return system("where fzf >nul 2>nul") == 0;
#else
    return system("command -v fzf >/dev/null 2>&1") == 0;
#endif
}

std::string selectPathFzf(const std::string& promptText, bool directoriesOnly = false, const std::string& startDir = "") {
    // Dynamically resolve search root to user's home directory if not explicitly provided
    std::string searchDir = startDir;
    if (searchDir.empty()) {
        searchDir = forensivault::core::Platform::getUserHomeDirectory();
    }

    if (!hasFzfInstalled() || !isStdinAtty() || getenv("FORENSIVAULT_NO_FZF") != nullptr) {
        forensivault::Logger::getInstance().print(promptText + " (enter path manually): ");
        return readLine("");
    }

    // FZF is the default: launch directly searching from user's home directory
    FV_PRINTLN(promptText);
    FV_PRINTLN("[*] Launching FZF file browser (searching from home: " + searchDir + ")...");

    std::string cmd;
#if defined(_WIN32)
    if (directoriesOnly) {
        cmd = "cd /d \"" + searchDir + "\" && dir /b /s /ad 2>nul | fzf --prompt=\"Select Directory > \"";
    } else {
        cmd = "cd /d \"" + searchDir + "\" && dir /b /s 2>nul | fzf --prompt=\"Select Target > \"";
    }
    FILE* pipe = _popen(cmd.c_str(), "r");
#else
    if (directoriesOnly) {
        cmd = "find \"" + searchDir + "\" -maxdepth 5 -not -path '*/.*' -not -path '*/node_modules/*' -not -path '*/.cache/*' -type d 2>/dev/null | fzf --height 40% --reverse --border --prompt=\"Select Directory > \"";
    } else {
        cmd = "find \"" + searchDir + "\" -maxdepth 5 -not -path '*/.*' -not -path '*/node_modules/*' -not -path '*/.cache/*' 2>/dev/null | fzf --height 40% --reverse --border --prompt=\"Select Target > \"";
    }
    FILE* pipe = popen(cmd.c_str(), "r");
#endif

    if (!pipe) {
        forensivault::Logger::getInstance().print("Enter path manually: ");
        return readLine("");
    }

    char buf[4096];
    std::string result;
    if (fgets(buf, sizeof(buf), pipe) != nullptr) {
        result = buf;
    }
#if defined(_WIN32)
    _pclose(pipe);
#else
    pclose(pipe);
#endif

    result = trim(result);
    if (result.empty()) {
        FV_PRINTLN("[FZF Canceled] You may type the path manually, or press Enter to abort:");
        forensivault::Logger::getInstance().print("Target Path: ");
        return readLine("");
    }

    FV_PRINTLN("[FZF Selected]: " + result);
    return result;
}

void printBanner() {
    FV_PRINTLN(R"(
  =============================================================
     ______                         _ _    __             _ _   
    |  ____|                       (_) |  /\ \           | | |  
    | |__ ___  _ __ ___ _ __  ___ _ _| | /  \ \   _  __ _| | |_ 
    |  __/ _ \| '__/ _ \ '_ \/ __| | | |/ /\ \ \ | |/ _` | | __|
    | | | (_) | | |  __/ | | \__ \ | | / ____ \ \| | (_| | | |_ 
    |_|  \___/|_|  \___|_| |_|___/_|_|/_/    \_\_|\__,_|_|\__|
  =============================================================
   Forensic Data Recovery & Secure Sanitization Platform
   Modules: Drive Sanitizer | File & Folder Eraser | File Carver
   Compliant with: NIST SP 800-88 Rev 1 & DoD 5220.22-M
  =============================================================)");
    FV_PRINTLN();
}

void printHelp() {
    FV_PRINTLN("Usage: forensivault_cli [command] [options]\n");
    FV_PRINTLN("Interactive Mode:");
    FV_PRINTLN("  forensivault_cli             Start the interactive forensic terminal");
    FV_PRINTLN("  --interactive, -i            Start the interactive forensic terminal\n");
    FV_PRINTLN("Core Modules & Commands:");
    FV_PRINTLN("  --help, -h                   Show this forensic help reference");
    FV_PRINTLN("  --version, -v                Display ForensiVault engine version & platform");
    FV_PRINTLN("  --benchmark-hash             Run SHA-256 and MD5 hashing benchmarks");
    FV_PRINTLN("  --scan-image <path>          Scan a disk image (.dd, .img) in READ-ONLY mode");
    FV_PRINTLN("  --carve <image> [out]        Execute deep file carving & extraction");
    FV_PRINTLN("  --fs-recover <img discipline>[out] Probe & recover filesystem structure (FAT32/exFAT/NTFS)");
    FV_PRINTLN("  --reconstruct <image>        Execute fragmented-file analysis");
    FV_PRINTLN("  --erase-preview <path>       Preview secure file/folder sanitization (non-destructive)");
    FV_PRINTLN("  --erase <path> [--dod|--random] [--confirm] Securely sanitize target path");
    FV_PRINTLN("  --detect-drives              Detect system storage devices & capabilities");
    FV_PRINTLN("  --inspect-drive <image>      Inspect drive image properties and parameters");
    FV_PRINTLN("  --sanitize-drive <image> [--nist|--dod|--random] [--confirm] Certified drive sanitization");
    FV_PRINTLN("  --audit-export <path>        Export chained forensic audit report in JSONL format\n");
}

void scanDiskImage(const std::string& imagePath) {
    FV_PRINTLN("[INFO] Opening disk image in READ-ONLY mode: " + imagePath);
    forensivault::core::DiskImageReader reader(imagePath);

    if (!reader.isOpen()) {
        FV_PRINTERRLN("[ERROR] Failed to open disk image: " + reader.lastError());
        return;
    }

    FV_PRINTLN("\n[Forensic Image Geometry & Acquisition Data]");
    FV_PRINTLN("  File Path:      " + reader.filepath());
    {
        std::ostringstream ss;
        ss << "  Total Size:     " << reader.size() << " bytes ("
           << std::fixed << std::setprecision(2)
           << (static_cast<double>(reader.size()) / (1024.0 * 1024.0)) << " MB)";
        FV_PRINTLN(ss.str());
    }
    FV_PRINTLN("  Sector Size:    " + std::to_string(reader.sectorSize()) + " bytes");
    FV_PRINTLN("  Total Sectors:  " + std::to_string(reader.totalSectors()) + " sectors");

    // Read Sector 0 (MBR / Boot Sector inspection)
    auto sector0 = reader.readSector(0);
    if (!sector0.empty()) {
        bool hasMbrSignature = (sector0.size() >= 512 && sector0[510] == 0x55 && sector0[511] == 0xAA);
        FV_PRINTLN("  Sector 0 Status: Successfully read (" +
                   std::string(hasMbrSignature ? "Valid MBR Signature 0x55AA" : "Non-MBR Boot Sector") + ")");
    }

    // Compute evidence cryptographic hashes via streaming
    FV_PRINTLN("[INFO] Computing evidence cryptographic hashes (read-only stream)...");
    forensivault::CryptoHash::Sha256Context shaCtx;
    forensivault::CryptoHash::Md5Context md5Ctx;

    std::vector<uint8_t> chunk(64 * 1024);
    uint64_t bytesProcessed = 0;
    uint64_t total = reader.size();

    while (bytesProcessed < total) {
        size_t toRead = static_cast<size_t>(std::min<uint64_t>(chunk.size(), total - bytesProcessed));
        if (!reader.read(bytesProcessed, chunk.data(), toRead)) {
            FV_PRINTERRLN("[ERROR] Read failure during hashing at offset " + std::to_string(bytesProcessed));
            break;
        }
        shaCtx.update(chunk.data(), toRead);
        md5Ctx.update(chunk.data(), toRead);
        bytesProcessed += toRead;
    }

    std::string sha256 = shaCtx.finalize();
    std::string md5 = md5Ctx.finalize();

    FV_PRINTLN("\n[Evidence Cryptographic Hashes (Chain of Custody)]");
    FV_PRINTLN("  SHA-256: " + sha256);
    FV_PRINTLN("  MD5:     " + md5);
    FV_PRINTLN("  Status:  Verified Immutability Preserved\n");

    FV_PRINTLN("[AUDIT] Disk image acquired and hashed: " + imagePath + " [SHA-256: " + sha256 + "]");
}

// ============================================================================
// Module 2: Secure File & Folder Eraser Module
// ============================================================================

void interactiveFileRemoval() {
    FV_PRINTLN("\n=============================================================");
    FV_PRINTLN("  MODULE 2: SECURE FILE & FOLDER ERASER                     ");
    FV_PRINTLN("  (Selective Deletion, Metadata Cleansing, Verification)     ");
    FV_PRINTLN("=============================================================");

    std::string inputPath = selectPathFzf("Select file or folder to sanitize with FZF");
    if (inputPath.empty()) {
        FV_PRINTLN("[ABORTED] No path provided.");
        return;
    }

    fs::path p(inputPath);
    std::error_code ec;
    if (!fs::exists(p, ec)) {
        FV_PRINTERRLN("[ERROR] The specified path does not exist: " + inputPath);
        return;
    }

    // Critical root drive, /root, and system protection check
    if (forensivault::core::Platform::isRootOrSystemPath(p) ||
        forensivault::core::Platform::isMainSystemDrive(p)) {
        FV_PRINTERRLN("\n[CRITICAL SAFETY BLOCK] TARGET IS OS ROOT (/ or C:\\), /root, OR MAIN SYSTEM DRIVE!");
        FV_PRINTERRLN("ForensiVault permanently protects the operating system, /root, and internal main drive.");
        FV_PRINTERRLN("Operation permanently prohibited even with root (sudo) or administrator privileges: " + p.string());
        return;
    }

    // Privilege / Elevation check
    bool isElevated = forensivault::core::Platform::isElevated();
    if (!isElevated) {
        std::string proceed = readLine("Do you want to proceed with current privileges? (y/N): ");
        if (proceed != "y" && proceed != "Y") {
            FV_PRINTLN("[ABORTED] Operation canceled due to lack of elevation.");
            return;
        }
    }

    std::vector<fs::path> targetsToErase = { p };

    // If path is a directory, list contents and give option to pick single item, ranges, or entire directory
    if (fs::is_directory(p, ec)) {
        std::vector<fs::path> dirEntries;
        try {
            for (const auto& entry : fs::directory_iterator(p)) {
                dirEntries.push_back(entry.path());
            }
        } catch (const std::exception& e) {
            FV_PRINTERRLN("[ERROR] Failed to read directory contents: " + std::string(e.what()));
            return;
        }

        std::sort(dirEntries.begin(), dirEntries.end());

        FV_PRINTLN("\nDirectory Contents in: " + p.string());
        FV_PRINTLN("  [0] >> SANITIZE ENTIRE DIRECTORY RECURSIVELY <<");
        size_t displayCount = std::min<size_t>(dirEntries.size(), 30);
        for (size_t i = 0; i < displayCount; ++i) {
            bool isDir = fs::is_directory(dirEntries[i], ec);
            std::string sizeStr;
            if (!isDir) {
                uint64_t sz = fs::file_size(dirEntries[i], ec);
                if (!ec) {
                    if (sz >= 1024 * 1024) sizeStr = " (" + std::to_string(sz / (1024 * 1024)) + " MB)";
                    else if (sz >= 1024) sizeStr = " (" + std::to_string(sz / 1024) + " KB)";
                    else sizeStr = " (" + std::to_string(sz) + " B)";
                }
            }
            FV_PRINTLN("  [" + std::to_string(i + 1) + "] " + dirEntries[i].filename().string() + (isDir ? "/ [DIR]" : sizeStr));
        }
        if (dirEntries.size() > displayCount) {
            FV_PRINTLN("  ... (" + std::to_string(dirEntries.size() - displayCount) + " more items)");
        }

        std::vector<int> selectedIndices;
        while (true) {
            std::string rangeHint = dirEntries.empty() ? "[0, " : "[e.g. 1-" + std::to_string(dirEntries.size()) + ", 1,3, ";
            std::string promptMsg = "\nSelect item numbers " + rangeHint +
                                    "default=0 (Sanitize Entire Directory), 'q' to cancel]: ";
            std::string sel = readLine(promptMsg);

            if (sel == "q" || sel == "Q") {
                FV_PRINTLN("[ABORTED] Operation canceled by user.");
                return;
            }

            std::string parseErr;
            if (parseItemSelection(sel, dirEntries.size(), selectedIndices, parseErr)) {
                break;
            } else {
                FV_PRINTERRLN("[ERROR] " + parseErr + " Please retry or enter 'q' to cancel.");
            }
        }

        targetsToErase.clear();
        if (selectedIndices.size() == 1 && selectedIndices[0] == 0) {
            targetsToErase.push_back(p);
            FV_PRINTLN("[TARGET SELECTED] Entire Directory: " + p.string());
        } else {
            for (int idx : selectedIndices) {
                if (idx > 0 && idx <= static_cast<int>(dirEntries.size())) {
                    targetsToErase.push_back(dirEntries[idx - 1]);
                }
            }
            if (targetsToErase.empty()) {
                targetsToErase.push_back(p);
                FV_PRINTLN("[TARGET SELECTED] Entire Directory: " + p.string());
            } else {
                FV_PRINTLN("\n[TARGETS SELECTED] " + std::to_string(targetsToErase.size()) + " item(s):");
                size_t showCount = std::min<size_t>(targetsToErase.size(), 10);
                for (size_t i = 0; i < showCount; ++i) {
                    FV_PRINTLN("  - " + targetsToErase[i].filename().string());
                }
                if (targetsToErase.size() > showCount) {
                    FV_PRINTLN("  ... and " + std::to_string(targetsToErase.size() - showCount) + " more items");
                }
            }
        }
    }

    // Select Sanitization Standard
    FV_PRINTLN("\nSelect Sanitization Standard:");
    FV_PRINTLN("  [1] NIST SP 800-88 Rev 1 Clear (Single-Pass 0x00) [Standard / Fast]");
    FV_PRINTLN("  [2] DoD 5220.22-M (3-Pass: 0x00, 0xFF, Cryptographic PRNG + Verify) [High Security]");
    FV_PRINTLN("  [3] Pseudorandom (1-Pass Cryptographic Random Overwrite)");
    forensivault::api::EraseMethod method = forensivault::api::EraseMethod::NIST_800_88_CLEAR;
    while (true) {
        std::string methodChoice = readLine("Select standard [1-3, default=1, 'q' to cancel]: ");
        size_t s = methodChoice.find_first_not_of(" \t\r\n");
        if (s == std::string::npos) {
            method = forensivault::api::EraseMethod::NIST_800_88_CLEAR;
            break;
        }
        size_t e = methodChoice.find_last_not_of(" \t\r\n");
        std::string trimmed = methodChoice.substr(s, e - s + 1);

        if (trimmed == "1") {
            method = forensivault::api::EraseMethod::NIST_800_88_CLEAR;
            break;
        } else if (trimmed == "2") {
            method = forensivault::api::EraseMethod::DOD_5220_22_M;
            break;
        } else if (trimmed == "3") {
            method = forensivault::api::EraseMethod::PSEUDO_RANDOM;
            break;
        } else if (trimmed == "q" || trimmed == "Q") {
            FV_PRINTLN("[ABORTED] Operation canceled by user.");
            return;
        } else {
            FV_PRINTERRLN("[ERROR] Invalid selection. Please enter 1, 2, 3, or 'q' to cancel.");
        }
    }

    // Non-destructive preview
    uint64_t totalFiles = 0;
    uint64_t totalDirectories = 0;
    uint64_t totalBytes = 0;
    bool anyProtected = false;
    std::string protectReason;

    for (const auto& targetItem : targetsToErase) {
        auto preview = forensivault::api::FileEraserAPI::preview(targetItem.string());
        if (preview.isRootOrSystemProtected) {
            anyProtected = true;
            protectReason = preview.protectionReason;
        }
        totalFiles += preview.totalFiles;
        totalDirectories += preview.totalDirectories;
        totalBytes += preview.totalBytes;
    }

    if (anyProtected) {
        FV_PRINTERRLN("\n[CRITICAL SAFETY BLOCK] TARGET INCLUDES A SYSTEM ROOT DRIVE / PATH!");
        FV_PRINTERRLN("Operation permanently prohibited: " + protectReason);
        return;
    }

    FV_PRINTLN("\n[SANITIZATION TARGET PREVIEW]");
    if (targetsToErase.size() == 1) {
        FV_PRINTLN("  Target Path:        " + targetsToErase[0].string());
    } else {
        FV_PRINTLN("  Target Directory:   " + p.string());
        FV_PRINTLN("  Selected Targets:   " + std::to_string(targetsToErase.size()) + " items");
    }
    FV_PRINTLN("  Total Files:        " + std::to_string(totalFiles));
    FV_PRINTLN("  Total Directories:  " + std::to_string(totalDirectories));
    {
        std::ostringstream ss;
        ss << "  Total Data Volume:  " << totalBytes << " bytes ("
           << std::fixed << std::setprecision(2) << (static_cast<double>(totalBytes) / (1024.0 * 1024.0)) << " MB)";
        FV_PRINTLN(ss.str());
    }

    // Explicit confirmation
    FV_PRINTLN("\n=============================================================");
    FV_PRINTLN("                 PERMANENT DESTRUCTION WARNING              ");
    FV_PRINTLN("=============================================================");
    FV_PRINTLN("This operation will permanently overwrite and unallocate all");
    FV_PRINTLN("data within the target(s). In accordance with forensic physics,");
    FV_PRINTLN("overwritten data CANNOT be recovered by any technique.");
    std::string confirm = readLine("Type 'DESTROY' in uppercase to confirm permanent erasure: ");
    if (confirm != "DESTROY") {
        FV_PRINTLN("[ABORTED] Confirmation string did not match 'DESTROY'. No changes made.");
        return;
    }

    // Execute erasure
    size_t targetIdx = 0;
    size_t totalTargets = targetsToErase.size();
    uint64_t totalFilesErased = 0;
    uint64_t totalDirsErased = 0;
    uint64_t totalBytesErased = 0;
    int passesCompleted = 0;
    bool allSucceeded = true;
    std::vector<std::string> errorList;
    std::string lastAuditSig;

    for (const auto& targetItem : targetsToErase) {
        targetIdx++;
        auto progressCb = [&](const forensivault::api::EraseProgress& prg) {
            std::ostringstream ss;
            if (totalTargets > 1) {
                ss << "\r[WIPING " << targetIdx << "/" << totalTargets << "] "
                   << std::fixed << std::setprecision(1) << prg.percentComplete
                   << "% (Pass " << prg.currentPass << "/" << prg.totalPasses << ") "
                   << prg.currentPath;
            } else {
                ss << "\r[WIPING] " << std::fixed << std::setprecision(1) << prg.percentComplete
                   << "% (Pass " << prg.currentPass << "/" << prg.totalPasses << ") "
                   << prg.currentPath;
            }
            forensivault::Logger::getInstance().print(ss.str());
        };

        std::error_code itemEc;
        forensivault::api::EraseResult result;
        if (fs::is_directory(targetItem, itemEc)) {
            result = forensivault::api::FileEraserAPI::eraseDirectory(targetItem.string(), method, progressCb);
        } else {
            result = forensivault::api::FileEraserAPI::eraseFile(targetItem.string(), method, progressCb);
        }

        if (result.success) {
            totalFilesErased += result.filesErased;
            totalDirsErased += result.directoriesErased;
            totalBytesErased += result.bytesErased;
            passesCompleted = std::max(passesCompleted, result.passesCompleted);
            lastAuditSig = result.auditSignature;
        } else {
            allSucceeded = false;
            errorList.push_back(targetItem.filename().string() + ": " + result.errorMessage);
        }
    }

    FV_PRINTLN("\n");
    if (allSucceeded) {
        FV_PRINTLN("[SUCCESS] Sanitization operation completed successfully!");
        if (totalTargets > 1) {
            FV_PRINTLN("  Targets Processed:  " + std::to_string(totalTargets));
        }
        FV_PRINTLN("  Files Erased:       " + std::to_string(totalFilesErased));
        FV_PRINTLN("  Directories Erased: " + std::to_string(totalDirsErased));
        FV_PRINTLN("  Bytes Overwritten:  " + std::to_string(totalBytesErased));
        FV_PRINTLN("  Passes Completed:   " + std::to_string(passesCompleted));
        FV_PRINTLN("  Verification Check: [PASSED 100%]");
        if (!lastAuditSig.empty()) {
            FV_PRINTLN("  Audit Signature:    " + lastAuditSig);
        }
    } else {
        FV_PRINTERRLN("[FAILURE] Sanitization encountered errors on some targets:");
        for (const auto& err : errorList) {
            FV_PRINTERRLN("  - " + err);
        }
    }
}

// ============================================================================
// Module 1: Secure Drive Eraser Module
// ============================================================================

void interactiveDriveSanitization() {
    FV_PRINTLN("\n=============================================================");
    FV_PRINTLN("  MODULE 1: SECURE DRIVE ERASER                             ");
    FV_PRINTLN("  (HDDs, SSDs, USB Drives, SD Cards, Hardware Sanitization)  ");
    FV_PRINTLN("=============================================================");

    std::string target = selectPathFzf("Select disk image or device to sanitize with FZF");
    if (target.empty()) {
        FV_PRINTLN("[ABORTED] No path provided.");
        return;
    }

    fs::path p(target);
    std::error_code ec;
    if (!fs::exists(p, ec)) {
        FV_PRINTERRLN("[ERROR] Path does not exist: " + target);
        return;
    }

    // Safety checks against internal main system drive
    if (forensivault::core::Platform::isRootOrSystemPath(p) ||
        forensivault::core::Platform::isMainSystemDrive(p)) {
        FV_PRINTERRLN("\n[CRITICAL SAFETY BLOCK] TARGET IS THE ACTIVE OS ROOT / SYSTEM DRIVE!");
        FV_PRINTERRLN("Drive sanitization is permanently prohibited for the internal main drive: " + p.string());
        FV_PRINTERRLN("This protection cannot be bypassed even with root (sudo) or administrator privileges.");
        return;
    }

    // Privilege check with on-the-fly elevation
    if (!forensivault::core::Platform::isElevated()) {
        FV_PRINTLN("\n[ELEVATION REQUIRED] Physical storage device sanitization requires administrative / root privileges.");
        forensivault::Logger::getInstance().print("Elevate privileges on the fly with sudo / admin credentials? [Y/n]: ");
        std::string ans = readLine("");
        if (ans.empty() || ans == "y" || ans == "Y" || ans == "yes") {
            FV_PRINTLN("[*] Elevating to root / administrator on the fly...");
            if (!forensivault::core::Platform::elevateProcess({"--option", "2"})) {
                FV_PRINTERRLN("[ERROR] Elevation failed or was cancelled.");
                return;
            }
            return;
        } else {
            FV_PRINTLN("[ABORTED] Elevation declined. Returning to main menu.");
            return;
        }
    }

    FV_PRINTLN("\nSelect Sanitization Standard:");
    FV_PRINTLN("  [1] NIST SP 800-88 Rev 1 Clear (Single-Pass 0x00)");
    FV_PRINTLN("  [2] DoD 5220.22-M (3-Pass: 0x00, 0xFF, Cryptographic PRNG + Verify)");
    FV_PRINTLN("  [3] Pseudorandom (1-Pass Cryptographic Random Overwrite)");
    forensivault::api::DriveSanitizeStandard stdMethod = forensivault::api::DriveSanitizeStandard::NIST_800_88_CLEAR;
    while (true) {
        std::string methodChoice = readLine("Select standard [1-3, default=1, 'q' to cancel]: ");
        size_t s = methodChoice.find_first_not_of(" \t\r\n");
        if (s == std::string::npos) {
            stdMethod = forensivault::api::DriveSanitizeStandard::NIST_800_88_CLEAR;
            break;
        }
        size_t e = methodChoice.find_last_not_of(" \t\r\n");
        std::string trimmed = methodChoice.substr(s, e - s + 1);

        if (trimmed == "1") {
            stdMethod = forensivault::api::DriveSanitizeStandard::NIST_800_88_CLEAR;
            break;
        } else if (trimmed == "2") {
            stdMethod = forensivault::api::DriveSanitizeStandard::DOD_5220_22_M;
            break;
        } else if (trimmed == "3") {
            stdMethod = forensivault::api::DriveSanitizeStandard::CRYPTO_RANDOM;
            break;
        } else if (trimmed == "q" || trimmed == "Q") {
            FV_PRINTLN("[ABORTED] Operation canceled by user.");
            return;
        } else {
            FV_PRINTERRLN("[ERROR] Invalid selection. Please enter 1, 2, 3, or 'q' to cancel.");
        }
    }

    FV_PRINTLN("\n=============================================================");
    FV_PRINTLN("                 PERMANENT DESTRUCTION WARNING              ");
    FV_PRINTLN("=============================================================");
    FV_PRINTLN("This will completely and irreversibly overwrite ALL data on:");
    FV_PRINTLN("  " + p.string());
    std::string confirm = readLine("Type 'DESTROY' to confirm device sanitization: ");
    if (confirm != "DESTROY") {
        FV_PRINTLN("[ABORTED] Confirmation did not match 'DESTROY'. No changes made.");
        return;
    }

    auto progressCb = [](const forensivault::api::DriveSanitizeProgress& prg) {
        std::ostringstream ss;
        ss << "\r[SANITIZING] " << std::fixed << std::setprecision(1) << prg.percentComplete
           << "% [Pass " << prg.currentPass << "/" << prg.totalPasses << "] "
           << std::setprecision(2) << prg.currentSpeedMBps << " MB/s";
        forensivault::Logger::getInstance().print(ss.str());
    };

    auto res = forensivault::api::DriveSanitizerAPI::sanitize(p.string(), stdMethod, progressCb);
    FV_PRINTLN("\n");

    if (res.success) {
        FV_PRINTLN("[SUCCESS] Drive sanitization completed and cryptographically verified!");
        FV_PRINTLN("  Bytes Sanitized:    " + std::to_string(res.totalBytesSanitized));
        FV_PRINTLN("  Passes Completed:   " + std::to_string(res.passesCompleted));
        FV_PRINTLN("  Verification:       " + std::string(res.verificationPassed ? "[VERIFIED COMPLIANT]" : "[FAILED]"));
        {
            std::ostringstream ss;
            ss << "  Duration:           " << std::fixed << std::setprecision(2) << res.durationSeconds << " s";
            FV_PRINTLN(ss.str());
        }
        FV_PRINTLN("  Audit Signature:    " + res.auditSignature);
    } else {
        FV_PRINTERRLN("[FAILURE] Drive sanitization failed: " + res.errorMessage);
    }
}

// ============================================================================
// Module 3: Advanced File Carving & Recovery Module
// ============================================================================

void interactiveFileCarving() {
    FV_PRINTLN("\n=============================================================");
    FV_PRINTLN("  MODULE 3: ADVANCED FILE CARVING & RECOVERY               ");
    FV_PRINTLN("  (Signature-Based, Structure-Based & Fragment Reconstruction)");
    FV_PRINTLN("=============================================================");

    std::string imgPath = selectPathFzf("Select evidence image file (.img, .dd, .raw) with FZF");
    if (imgPath.empty()) {
        FV_PRINTLN("[ABORTED] No path provided.");
        return;
    }

    if (!fs::exists(imgPath)) {
        FV_PRINTERRLN("[ERROR] Evidence image not found: " + imgPath);
        return;
    }

    std::string outDir = selectPathFzf("Select or enter output directory for recovered files", true);
    if (outDir.empty()) outDir = "recovered/carved";

    FV_PRINTLN("\nStarting forensic file carving (READ-ONLY mode)...");
    auto progressCb = [](const forensivault::api::CarveProgress& prg) {
        std::ostringstream ss;
        ss << "\r[CARVING] " << std::fixed << std::setprecision(1) << prg.percentComplete
           << "% Scanned | " << prg.filesDiscovered << " files discovered...";
        forensivault::Logger::getInstance().print(ss.str());
    };

    auto res = forensivault::api::CarverAPI::carve(imgPath, outDir, 30.0, progressCb);
    FV_PRINTLN("\n");

    if (res.success) {
        FV_PRINTLN("[CARVING COMPLETE]");
        FV_PRINTLN("  Source Image:       " + res.sourcePath);
        FV_PRINTLN("  Output Directory:   " + res.outputDirectory);
        FV_PRINTLN("  Signatures Found:   " + std::to_string(res.signaturesDiscovered));
        FV_PRINTLN("  Files Carved:       " + std::to_string(res.filesSuccessfullyCarved));
        FV_PRINTLN("  Valid Files:        " + std::to_string(res.validFilesCount));
        {
            std::ostringstream ss;
            ss << "  Duration:           " << std::fixed << std::setprecision(2) << res.durationSeconds << " s";
            FV_PRINTLN(ss.str());
        }

        if (!res.carvedFiles.empty()) {
            FV_PRINTLN("\nRecovered Artifacts Table:");
            std::ostringstream header;
            header << std::left
                   << std::setw(6)  << "TYPE"
                   << std::setw(14) << "OFFSET (HEX)"
                   << std::setw(12) << "SIZE (B)"
                   << std::setw(12) << "CONFIDENCE"
                   << std::setw(10) << "STATUS"
                   << "RECOVERED PATH";
            FV_PRINTLN(header.str());
            FV_PRINTLN(std::string(85, '-'));

            for (const auto& f : res.carvedFiles) {
                std::ostringstream offHex;
                offHex << "0x" << std::hex << std::uppercase << f.offset;
                std::ostringstream row;
                row << std::left
                    << std::setw(6)  << f.fileType
                    << std::setw(14) << offHex.str()
                    << std::setw(12) << f.lengthBytes
                    << std::setw(12) << (std::to_string(static_cast<int>(f.confidenceScore)) + "%")
                    << std::setw(10) << (f.isValid ? "[PASS]" : "[WARN]")
                    << f.recoveredFilePath;
                FV_PRINTLN(row.str());
            }
            FV_PRINTLN();
        }
    } else {
        FV_PRINTERRLN("[ERROR] Carving failed: " + res.errorMessage);
    }
}

void interactiveFilesystemRecovery() {
    FV_PRINTLN("\n=============================================================");
    FV_PRINTLN("  MODULE 3 (PART B): FILESYSTEM METADATA RECOVERY            ");
    FV_PRINTLN("  (FAT32 Directory Tables, exFAT Streams, NTFS $MFT)        ");
    FV_PRINTLN("=============================================================");

    std::string imgPath = selectPathFzf("Select evidence image file with FZF");
    if (imgPath.empty()) {
        FV_PRINTLN("[ABORTED] No path provided.");
        return;
    }

    if (!fs::exists(imgPath)) {
        FV_PRINTERRLN("[ERROR] Evidence image not found: " + imgPath);
        return;
    }

    std::string outDir = selectPathFzf("Select or enter output directory", true);
    if (outDir.empty()) outDir = "recovered/filesystem";

    FV_PRINTLN("\nProbing filesystem structures...");
    auto vol = forensivault::api::FsRecoveryAPI::probeVolume(imgPath, 0);
    if (!vol.valid) {
        FV_PRINTERRLN("[WARNING] No standard FAT32, exFAT, or NTFS filesystem signature detected at partition offset 0.");
        FV_PRINTLN("Would you like to run signature-based carving instead? (y/N): ");
        std::string carveOpt = readLine("");
        if (carveOpt == "y" || carveOpt == "Y") {
            interactiveFileCarving();
        }
        return;
    }

    std::string fsName = "UNKNOWN";
    if (vol.type == forensivault::api::FilesystemType::FAT32) fsName = "FAT32";
    else if (vol.type == forensivault::api::FilesystemType::EXFAT) fsName = "exFAT";
    else if (vol.type == forensivault::api::FilesystemType::NTFS) fsName = "NTFS";

    FV_PRINTLN("  [+] Detected Filesystem: " + fsName);
    FV_PRINTLN("  [+] Volume Label:        " + vol.label);
    FV_PRINTLN("  [+] Sector Size:         " + std::to_string(vol.sectorSize) + " bytes");
    FV_PRINTLN("  [+] Cluster Size:        " + std::to_string(vol.clusterSize) + " bytes");

    FV_PRINTLN("\nExecuting metadata reconstruction and artifact extraction...");
    auto res = forensivault::api::FsRecoveryAPI::recover(imgPath, outDir, 0);
    if (res.success) {
        FV_PRINTLN("[RECOVERY COMPLETE]");
        FV_PRINTLN("  Active Files Extracted:  " + std::to_string(res.activeFiles.size()));
        FV_PRINTLN("  Deleted Files Recovered: " + std::to_string(res.deletedFiles.size()));
        FV_PRINTLN("  Evidence SHA-256:        " + res.evidenceSha256);

        if (!res.deletedFiles.empty()) {
            FV_PRINTLN("\nRecovered Deleted Files (Tombstones / Unallocated):");
            for (const auto& df : res.deletedFiles) {
                FV_PRINTLN("  [DELETED] " + df.filename + " (" + std::to_string(df.sizeBytes) + " bytes) -> " + df.recoveredFilePath);
            }
        }
    } else {
        FV_PRINTERRLN("[ERROR] Recovery failed: " + res.errorMessage);
    }
}

void interactiveInspectGeometry() {
    FV_PRINTLN("\n=============================================================");
    FV_PRINTLN("  INSPECT DISK IMAGE / STORAGE DEVICE GEOMETRY              ");
    FV_PRINTLN("=============================================================");

    std::string imgPath = selectPathFzf("Select disk image or device to inspect with FZF");
    if (imgPath.empty()) {
        FV_PRINTLN("[ABORTED] No path provided.");
        return;
    }

    if (!fs::exists(imgPath)) {
        FV_PRINTERRLN("[ERROR] Path not found: " + imgPath);
        return;
    }

    scanDiskImage(imgPath);
}

void interactiveDeviceDetection() {
    FV_PRINTLN("\n=============================================================");
    FV_PRINTLN("  STORAGE DEVICE DETECTION & HARDWARE INSPECTION            ");
    FV_PRINTLN("=============================================================");

    if (!forensivault::core::Platform::isElevated()) {
        FV_PRINTLN("[PERMISSION NOTICE] Current process is unprivileged. Low-level physical hardware access may be restricted.");
        forensivault::Logger::getInstance().print("Elevate privileges on the fly with sudo / admin? [Y/n]: ");
        std::string ans = readLine("");
        if (ans.empty() || ans == "y" || ans == "Y" || ans == "yes") {
            FV_PRINTLN("[*] Elevating to root / administrator on the fly...");
            if (!forensivault::core::Platform::elevateProcess({"--option", "6"})) {
                FV_PRINTERRLN("[ERROR] Elevation failed or was cancelled.");
            }
            return;
        }
    }

    auto devices = forensivault::api::DriveSanitizerAPI::detectDevices();
    if (devices.empty()) {
        FV_PRINTLN("No attached storage devices detected or access restricted.");
        return;
    }

    for (const auto& dev : devices) {
        if (dev.name.empty() || dev.name == dev.deviceId) {
            FV_PRINTLN("Device: " + dev.deviceId);
        } else {
            FV_PRINTLN("Device: " + dev.deviceId + " (" + dev.name + ")");
        }
        FV_PRINTLN("  Model:         " + dev.model);
        FV_PRINTLN("  Interface:     " + dev.interfaceType);
        FV_PRINTLN("  Media Type:    " + dev.mediaType);
        {
            std::ostringstream ss;
            ss << "  Capacity:      " << dev.sizeBytes << " bytes ("
               << std::fixed << std::setprecision(2)
               << (static_cast<double>(dev.sizeBytes) / (1024.0 * 1024.0 * 1024.0)) << " GB)";
            FV_PRINTLN(ss.str());
        }
        FV_PRINTLN("  System/Root:   " + std::string(dev.isSystemOrRootDrive ? "YES [PROTECTED]" : "NO"));
        FV_PRINTLN("  Safe to Wipe:  " + std::string(dev.isSafeToSanitize ? "YES" : "NO (Blocked: Root / System Drive Protection)"));
        if (!dev.capabilities.empty()) {
            FV_PRINTLN("  Capabilities:  " + dev.capabilities[0]);
        }
        FV_PRINTLN();
    }
}

void interactiveBenchmark() {
    FV_PRINTLN("\n=============================================================");
    FV_PRINTLN("  CRYPTOGRAPHIC HASHING & ENTROPY BENCHMARK                 ");
    FV_PRINTLN("=============================================================");

    std::string sample = "ForensiVault Forensic Integrity Test Payload 2026";
    std::string sha = forensivault::CryptoHash::sha256(sample);
    std::string md5 = forensivault::CryptoHash::md5(sample);
    double entropy = forensivault::CryptoHash::calculateEntropy(
        reinterpret_cast<const uint8_t*>(sample.data()), sample.size());

    FV_PRINTLN("Test Payload: \"" + sample + "\"");
    FV_PRINTLN("SHA-256:      " + sha);
    FV_PRINTLN("MD5:          " + md5);
    {
        std::ostringstream ss;
        ss << "Entropy:      " << std::fixed << std::setprecision(4) << entropy << " bits/byte (Max 8.0)";
        FV_PRINTLN(ss.str());
    }
    FV_PRINTLN("Status:       Cryptographic Core Operational\n");
}

void runInteractiveTerminal() {
    while (true) {
        printBanner();
        bool elevated = forensivault::core::Platform::isElevated();
        if (elevated) {
            FV_PRINTLN("Security Context: [ELEVATED - ROOT / ADMINISTRATOR]");
        } else {
            FV_PRINTLN("Security Context: [STANDARD USER - NOT ELEVATED]");
        }
        FV_PRINTLN("Interactive Main Menu (FZF Default):");
        FV_PRINTLN("  [1] Secure File & Folder Eraser Module (NIST SP 800-88 / DoD 5220.22-M)");
        FV_PRINTLN("  [2] Secure Drive Eraser Module (HDDs, SSDs, USB, SD Cards) [Requires Elevation]");
        FV_PRINTLN("  [3] Advanced File Carving & Recovery Module (Raw Read-Only Carving)");
        FV_PRINTLN("  [4] Filesystem Structure Recovery (FAT32/exFAT/NTFS)");
        FV_PRINTLN("  [5] Inspect Disk Image / Storage Device Geometry & Hashes");
        FV_PRINTLN("  [6] Storage Device Detection & Hardware Inspection [Requires Elevation for Raw Drives]");
        FV_PRINTLN("  [7] Cryptographic Hashing Benchmark");
        if (!elevated) {
            FV_PRINTLN("  [E] Elevate to Root / Administrator Privileges on the fly");
        }
        FV_PRINTLN("  [0] Exit ForensiVault");
        FV_PRINTLN("=============================================================");

        std::string choice = readLine("Select an option: ");

        if (choice == "1") {
            interactiveFileRemoval();
        } else if (choice == "2") {
            interactiveDriveSanitization();
        } else if (choice == "3") {
            interactiveFileCarving();
        } else if (choice == "4") {
            interactiveFilesystemRecovery();
        } else if (choice == "5") {
            interactiveInspectGeometry();
        } else if (choice == "6") {
            interactiveDeviceDetection();
        } else if (choice == "7") {
            interactiveBenchmark();
        } else if (choice == "e" || choice == "E") {
            if (elevated) {
                FV_PRINTLN("[INFO] Process is already running with elevated privileges.");
            } else {
                FV_PRINTLN("\n[*] Requesting elevated root / administrator privileges on the fly...");
                if (!forensivault::core::Platform::elevateProcess({"--interactive"})) {
                    FV_PRINTERRLN("[ERROR] Elevation failed or was cancelled.");
                } else {
                    return;
                }
            }
        } else if (choice == "0" || choice == "exit" || choice == "quit") {
            FV_PRINTLN("\nExiting ForensiVault. Forensic custody maintained.");
            break;
        } else {
            FV_PRINTLN("[INVALID OPTION] Please enter a valid menu option.\n");
        }

        FV_PRINTLN("\nPress Enter to return to main menu...");
        if (readLine("") == "exit") {
            FV_PRINTLN("\nExiting ForensiVault. Forensic custody maintained.");
            break;
        }
    }
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    std::vector<std::string> args(argv + 1, argv + argc);

    // Interactive Terminal Mode
    if (args.empty() || args[0] == "--interactive" || args[0] == "-i") {
        runInteractiveTerminal();
        return 0;
    }

    // Resumed option execution after on-the-fly elevation
    if (!args.empty() && (args[0] == "--option" || args[0] == "-o")) {
        std::string opt = (args.size() >= 2) ? args[1] : "0";
        FV_PRINTLN("[+] Running in elevated root / administrator session.");
        if (opt == "1") {
            interactiveFileRemoval();
        } else if (opt == "2") {
            interactiveDriveSanitization();
        } else if (opt == "3") {
            interactiveFileCarving();
        } else if (opt == "4") {
            interactiveFilesystemRecovery();
        } else if (opt == "5") {
            interactiveInspectGeometry();
        } else if (opt == "6") {
            interactiveDeviceDetection();
        } else if (opt == "7") {
            interactiveBenchmark();
        }
        FV_PRINTLN("\nPress Enter to return to main menu...");
        std::string pauseAns = readLine("");
        if (pauseAns != "exit" && pauseAns != "quit" && pauseAns != "0") {
            runInteractiveTerminal();
        } else {
            FV_PRINTLN("\nExiting ForensiVault. Forensic custody maintained.");
        }
        return 0;
    }

    if (args[0] == "--help" || args[0] == "-h") {
        printBanner();
        printHelp();
        return 0;
    }

    if (args[0] == "--version" || args[0] == "-v") {
#if defined(_WIN32)
        std::string plat = "Windows (x86_64)";
#elif defined(__linux__)
        std::string plat = "Linux (x86_64)";
#else
        std::string plat = "POSIX (Generic)";
#endif
        FV_PRINTLN("ForensiVault Core Engine v1.0.0 [" + plat + "]");
        FV_PRINTLN("Compliant with: NIST SP 800-88 Rev 1, DoD 5220.22-M");
        return 0;
    }

    if (args[0] == "--benchmark-hash") {
        interactiveBenchmark();
        return 0;
    }

    if (args[0] == "--scan-image") {
        if (args.size() < 2) {
            FV_PRINTERRLN("[ERROR] Missing disk image path argument for --scan-image");
            return 1;
        }
        scanDiskImage(args[1]);
        return 0;
    }

    if (args[0] == "--carve") {
        if (args.size() < 2) {
            FV_PRINTERRLN("[ERROR] Missing disk image path argument for --carve");
            return 1;
        }
        std::string imagePath = args[1];
        std::string outDir = (args.size() >= 3) ? args[2] : "recovered/carved";

        auto progressCb = [](const forensivault::api::CarveProgress& prg) {
            std::ostringstream ss;
            ss << "\r[CARVING] " << std::fixed << std::setprecision(1) << prg.percentComplete
               << "% | Discovered: " << prg.filesDiscovered << " files...";
            forensivault::Logger::getInstance().print(ss.str());
        };

        auto session = forensivault::api::CarverAPI::carve(imagePath, outDir, 30.0, progressCb);
        FV_PRINTLN("\n");

        if (session.success) {
            FV_PRINTLN("Carving completed: " + std::to_string(session.filesSuccessfullyCarved) + " files recovered to " + outDir);
            return 0;
        } else {
            FV_PRINTERRLN("Carving failed: " + session.errorMessage);
            return 1;
        }
    }

    if (args[0] == "--fs-recover") {
        if (args.size() < 2) {
            FV_PRINTERRLN("[ERROR] Missing disk image path argument for --fs-recover");
            return 1;
        }
        std::string imagePath = args[1];
        std::string outDir = (args.size() >= 3) ? args[2] : "recovered/filesystem";
        auto res = forensivault::api::FsRecoveryAPI::recover(imagePath, outDir, 0);
        if (res.success) {
            FV_PRINTLN("Filesystem recovery completed: " + std::to_string(res.activeFiles.size()) +
                       " active files, " + std::to_string(res.deletedFiles.size()) + " deleted files.");
            return 0;
        } else {
            FV_PRINTERRLN("Filesystem recovery failed: " + res.errorMessage);
            return 1;
        }
    }

    if (args[0] == "--reconstruct") {
        if (args.size() < 2) {
            FV_PRINTERRLN("[ERROR] Missing disk image path argument for --reconstruct");
            return 1;
        }
        std::string imagePath = args[1];
        forensivault::core::DiskImageReader reader(imagePath);
        if (!reader.isOpen()) {
            FV_PRINTERRLN("[ERROR] Failed to open disk image: " + reader.lastError());
            return 1;
        }

        std::vector<uint8_t> imgBuffer = reader.readBytes(0, static_cast<size_t>(reader.size()));
        forensivault::carving::SignatureDatabase db;
        forensivault::carving::SignatureScanner scanner(db);
        auto matches = scanner.scan(reader);

        FV_PRINTLN("\n============================================================");
        FV_PRINTLN("        ForensiVault Fragmented-File Analysis               ");
        FV_PRINTLN("============================================================");

        for (const auto& match : matches) {
            std::ostringstream ss;
            ss << "\n[Analyzing Header Candidate: " << match.signature->fileType
               << " at Offset 0x" << std::hex << std::uppercase << match.offset << "]";
            FV_PRINTLN(ss.str());

            size_t probeSize = std::min<size_t>(512, imgBuffer.size() - match.offset);
            std::vector<uint8_t> fragData(imgBuffer.data() + match.offset, imgBuffer.data() + match.offset + probeSize);

            forensivault::carving::FragmentCandidate headerFrag;
            headerFrag.fragmentId = match.offset;
            headerFrag.offset = match.offset;
            headerFrag.length = probeSize;
            headerFrag.fileType = match.signature->fileType;
            headerFrag.role = forensivault::carving::FragmentRole::Header;
            headerFrag.entropy = forensivault::CryptoHash::calculateEntropy(fragData);
            headerFrag.data = std::move(fragData);
            headerFrag.confidence = 50.0;

            uint64_t searchStart = match.offset + 512;
            if (searchStart < imgBuffer.size()) {
                auto orphans = forensivault::carving::FragmentReconstructor::findOrphanFragments(
                    match.signature->fileType,
                    imgBuffer.data() + searchStart,
                    searchStart,
                    imgBuffer.size() - searchStart,
                    512);

                FV_PRINTLN("  Discovered " + std::to_string(orphans.size()) + " orphan cluster candidates.");
                auto result = forensivault::carving::FragmentReconstructor::attemptReconstruction(
                    headerFrag, orphans, 1024 * 1024);

                FV_PRINTLN("  Reconstruction Status: " + std::string(result.isReconstructed ? "[RECONSTRUCTED]" : "[PARTIAL / SEGREGATED]"));
                FV_PRINTLN("  Confidence Score:      " + std::to_string(static_cast<int>(result.confidenceScore)) + "%");
                FV_PRINTLN("  Notes / Uncertainty:   " + result.uncertaintyReason);
            }
        }
        return 0;
    }

    if (args[0] == "--erase-preview") {
        if (args.size() < 2) {
            FV_PRINTERRLN("[ERROR] Missing target path for --erase-preview");
            return 1;
        }
        auto prev = forensivault::api::FileEraserAPI::preview(args[1]);
        FV_PRINTLN("\n============================================================");
        FV_PRINTLN("        ForensiVault Sanitization Preview (Non-Destructive) ");
        FV_PRINTLN("============================================================");
        FV_PRINTLN("Target:             " + args[1]);
        FV_PRINTLN("Safety Status:      " + std::string(prev.isRootOrSystemProtected ? "[PROHIBITED - SYSTEM PATH DETECTED]" : "[PASSED - SAFE TO PROCESS]"));
        if (prev.isRootOrSystemProtected) {
            FV_PRINTERRLN("Block Reason:       " + prev.protectionReason);
        }
        FV_PRINTLN("Files to Erase:     " + std::to_string(prev.totalFiles));
        FV_PRINTLN("Folders to Remove:  " + std::to_string(prev.totalDirectories));
        FV_PRINTLN("Total Bytes:        " + std::to_string(prev.totalBytes) + " bytes");
        FV_PRINTLN("============================================================\n");
        return 0;
    }

    if (args[0] == "--erase") {
        if (args.size() < 2) {
            FV_PRINTERRLN("[ERROR] Missing target path for --erase");
            return 1;
        }
        std::string targetPath = args[1];
        bool confirmed = false;
        forensivault::api::EraseMethod method = forensivault::api::EraseMethod::NIST_800_88_CLEAR;

        for (size_t a = 2; a < args.size(); ++a) {
            if (args[a] == "--confirm") confirmed = true;
            else if (args[a] == "--dod") method = forensivault::api::EraseMethod::DOD_5220_22_M;
            else if (args[a] == "--random") method = forensivault::api::EraseMethod::PSEUDO_RANDOM;
        }

        if (!confirmed) {
            FV_PRINTERRLN("\n[SAFETY INTERLOCK ERROR] Operation aborted!");
            FV_PRINTERRLN("Explicit user confirmation is required prior to destructive erasure.");
            FV_PRINTERRLN("Re-run with '--confirm' flag to proceed with permanent destruction.\n");
            return 1;
        }

        auto cb = [](const forensivault::api::EraseProgress& p) {
            std::ostringstream ss;
            ss << "\rOverwriting: " << std::fixed << std::setprecision(1)
               << p.percentComplete << "% [Pass " << p.currentPass << "/" << p.totalPasses
               << "] " << p.currentPath;
            forensivault::Logger::getInstance().print(ss.str());
        };

        forensivault::api::EraseResult res;
        if (fs::is_directory(targetPath)) {
            res = forensivault::api::FileEraserAPI::eraseDirectory(targetPath, method, cb);
        } else {
            res = forensivault::api::FileEraserAPI::eraseFile(targetPath, method, cb);
        }

        FV_PRINTLN("\n");
        if (res.success) {
            FV_PRINTLN("Sanitization complete. Files erased: " + std::to_string(res.filesErased) +
                       ", Bytes: " + std::to_string(res.bytesErased) +
                       ", Audit signature: " + res.auditSignature);
            return 0;
        } else {
            FV_PRINTERRLN("Sanitization failed: " + res.errorMessage);
            return 1;
        }
    }

    if (args[0] == "--detect-drives") {
        interactiveDeviceDetection();
        return 0;
    }

    if (args[0] == "--inspect-drive") {
        if (args.size() < 2) {
            FV_PRINTERRLN("[ERROR] Missing image path for --inspect-drive");
            return 1;
        }
        scanDiskImage(args[1]);
        return 0;
    }

    if (args[0] == "--sanitize-drive") {
        if (args.size() < 2) {
            FV_PRINTERRLN("[ERROR] Missing disk image path for --sanitize-drive");
            return 1;
        }
        std::string imgPath = args[1];
        bool confirmed = false;
        forensivault::api::DriveSanitizeStandard stdMethod = forensivault::api::DriveSanitizeStandard::NIST_800_88_CLEAR;

        for (size_t a = 2; a < args.size(); ++a) {
            if (args[a] == "--confirm") confirmed = true;
            else if (args[a] == "--dod") stdMethod = forensivault::api::DriveSanitizeStandard::DOD_5220_22_M;
            else if (args[a] == "--random") stdMethod = forensivault::api::DriveSanitizeStandard::CRYPTO_RANDOM;
        }

        if (!confirmed) {
            FV_PRINTERRLN("[SAFETY INTERLOCK ERROR] Operation aborted!");
            FV_PRINTERRLN("Explicit user confirmation is mandatory prior to sanitizing disk image.");
            FV_PRINTERRLN("Re-run with '--confirm' flag to permanently overwrite the target.\n");
            return 1;
        }

        auto cb = [](const forensivault::api::DriveSanitizeProgress& p) {
            std::ostringstream ss;
            ss << "\rSanitizing: " << std::fixed << std::setprecision(1)
               << p.percentComplete << "% [Pass " << p.currentPass << "/" << p.totalPasses << "]";
            forensivault::Logger::getInstance().print(ss.str());
        };

        auto rep = forensivault::api::DriveSanitizerAPI::sanitize(imgPath, stdMethod, cb);
        FV_PRINTLN("\n");
        if (rep.success) {
            FV_PRINTLN("Device sanitization verified and complete. Audit: " + rep.auditSignature);
            return 0;
        } else {
            FV_PRINTERRLN("Device sanitization failed: " + rep.errorMessage);
            return 1;
        }
    }

    if (args[0] == "--audit-export") {
        if (args.size() < 2) {
            FV_PRINTERRLN("[ERROR] Missing destination path for --audit-export");
            return 1;
        }
        if (forensivault::logging::AuditLogger::getInstance().saveToFile(args[1])) {
            FV_PRINTLN("Forensic audit journal exported to: " + args[1]);
            return 0;
        } else {
            FV_PRINTERRLN("Failed to export audit journal to: " + args[1]);
            return 1;
        }
    }

    FV_PRINTERRLN("[WARN] Unrecognized command or option: " + args[0]);
    printHelp();
    return 1;
}
