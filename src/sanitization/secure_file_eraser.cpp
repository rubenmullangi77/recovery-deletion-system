#include "sanitization/secure_file_eraser.hpp"
#include "sanitization/system_protection.hpp"
#include "logging/audit_logger.hpp"
#include <fstream>
#include <filesystem>
#include <random>
#include <algorithm>
#include <cstring>
#include <iostream>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <io.h>
#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#endif

namespace fs = std::filesystem;

namespace forensivault {
namespace sanitization {

namespace {

void flushToDisk(std::fstream& fsFile, const std::string& filepath) {
    fsFile.flush();
#if defined(_WIN32)
    HANDLE h = CreateFileA(filepath.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(h);
        CloseHandle(h);
    }
#elif defined(__linux__)
    int fd = ::open(filepath.c_str(), O_WRONLY);
    if (fd >= 0) {
        fdatasync(fd);
        ::close(fd);
    }
#elif defined(__unix__) || defined(__APPLE__)
    int fd = ::open(filepath.c_str(), O_WRONLY);
    if (fd >= 0) {
        fsync(fd);
        ::close(fd);
    }
#endif
}

} // anonymous namespace

int SecureFileEraser::getPassCount(SanitizationMethod method) {
    switch (method) {
        case SanitizationMethod::DOD_5220_22_M:
            return 3;
        case SanitizationMethod::NIST_800_88_CLEAR:
        case SanitizationMethod::PSEUDORANDOM_1_PASS:
        case SanitizationMethod::ZERO_FILL:
        default:
            return 1;
    }
}

std::string SecureFileEraser::generateRandomName(size_t length) {
    static const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> dist(0, sizeof(charset) - 2);

    std::string s;
    s.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        s += charset[dist(gen)];
    }
    return s;
}

bool SecureFileEraser::overwritePayload(
    const std::string& filepath,
    uint64_t fileSize,
    SanitizationMethod method,
    ProgressCallback callback) {

    int totalPasses = getPassCount(method);
    const size_t chunkSize = 64 * 1024; // 64 KB sector-aligned chunk buffer
    std::vector<uint8_t> buffer(chunkSize);

    std::random_device rd;
    std::mt19937_64 rng(rd());

    std::fstream file(filepath, std::ios::in | std::ios::out | std::ios::binary);
    if (!file) {
        return false;
    }

    for (int pass = 1; pass <= totalPasses; ++pass) {
        file.seekp(0, std::ios::beg);
        uint64_t bytesWrittenThisPass = 0;

        // Determine pattern for this pass
        uint8_t fixedByte = 0x00;
        bool isRandomPass = false;

        if (method == SanitizationMethod::DOD_5220_22_M) {
            if (pass == 1) fixedByte = 0x00;
            else if (pass == 2) fixedByte = 0xFF;
            else isRandomPass = true;
        } else if (method == SanitizationMethod::PSEUDORANDOM_1_PASS) {
            isRandomPass = true;
        } else {
            fixedByte = 0x00;
        }

        while (bytesWrittenThisPass < fileSize) {
            size_t toWrite = static_cast<size_t>(std::min<uint64_t>(chunkSize, fileSize - bytesWrittenThisPass));

            if (isRandomPass) {
                // Fill buffer with 64-bit random words
                size_t words = toWrite / sizeof(uint64_t);
                uint64_t* ptr = reinterpret_cast<uint64_t*>(buffer.data());
                for (size_t w = 0; w < words; ++w) {
                    ptr[w] = rng();
                }
                size_t rem = toWrite % sizeof(uint64_t);
                if (rem > 0) {
                    uint64_t lastWord = rng();
                    std::memcpy(buffer.data() + words * sizeof(uint64_t), &lastWord, rem);
                }
            } else {
                std::fill(buffer.begin(), buffer.begin() + toWrite, fixedByte);
            }

            file.write(reinterpret_cast<const char*>(buffer.data()), toWrite);
            if (!file) {
                return false;
            }

            bytesWrittenThisPass += toWrite;

            if (callback) {
                EraseProgress prog;
                prog.current_file = filepath;
                prog.current_file_index = 1;
                prog.total_files = 1;
                prog.current_pass = pass;
                prog.total_passes = totalPasses;
                prog.bytes_processed_file = bytesWrittenThisPass;
                prog.file_size_bytes = fileSize;
                prog.total_bytes_processed = (static_cast<uint64_t>(pass - 1) * fileSize) + bytesWrittenThisPass;
                prog.total_bytes_all = static_cast<uint64_t>(totalPasses) * fileSize;
                prog.percentage = (static_cast<double>(prog.total_bytes_processed) / prog.total_bytes_all) * 100.0;
                callback(prog);
            }
        }

        flushToDisk(file, filepath);
    }

    file.close();
    return true;
}

void SecureFileEraser::shredMetadataAndUnlink(const std::string& filepath) {
    try {
        fs::path p(filepath);
        if (!fs::exists(p)) return;

        // Truncate length to 0
        fs::resize_file(p, 0);

        // Rename 3 times to random strings to overwrite directory entry
        std::string dir = p.parent_path().string();
        std::string currentPath = filepath;
        size_t stemLen = std::max<size_t>(8, p.stem().string().length());

        for (int i = 0; i < 3; ++i) {
            std::string randomName = generateRandomName(stemLen) + ".tmp";
            fs::path newPath = fs::path(dir) / randomName;
            std::error_code ec;
            fs::rename(currentPath, newPath, ec);
            if (!ec) {
                currentPath = newPath.string();
            }
        }

        // Final unlink
        std::error_code ec;
        fs::remove(currentPath, ec);
    } catch (...) {
        // Best effort metadata shredding
    }
}

VerificationResult SecureFileEraser::eraseFile(
    const std::string& filepath,
    SanitizationMethod method,
    ProgressCallback callback) {

    VerificationResult result;
    result.limitations = getMethodLimitations(method);

    // 1. Safety check
    std::string blockReason;
    if (SystemProtectionGuard::isProtected(filepath, blockReason)) {
        result.is_verified = false;
        result.details = "SECURITY INTERLOCK BLOCKED: " + blockReason;
        logging::AuditLogger::getInstance().logEvent(
            "SAFETY_BLOCK", filepath, getMethodDescription(method), "BLOCKED", result.details);
        return result;
    }

    // 2. Existence and size check
    std::error_code ec;
    if (!fs::exists(filepath, ec) || !fs::is_regular_file(filepath, ec)) {
        result.is_verified = false;
        result.details = "File does not exist or is not a regular file.";
        return result;
    }

    uint64_t fileSize = fs::file_size(filepath, ec);
    if (ec) {
        result.is_verified = false;
        result.details = "Unable to read file size: " + ec.message();
        return result;
    }

    // 3. Multi-pass overwrite
    if (fileSize > 0) {
        if (!overwritePayload(filepath, fileSize, method, callback)) {
            result.is_verified = false;
            result.details = "Overwrite failed: IO error writing sectors.";
            logging::AuditLogger::getInstance().logEvent(
                "SECURE_FILE_ERASE", filepath, getMethodDescription(method), "FAILED", result.details);
            return result;
        }

        // 4. Pre-unlink verification
        result = verification::EraseVerification::verifyOverwrittenFile(filepath, method, fileSize);
        if (!result.is_verified) {
            logging::AuditLogger::getInstance().logEvent(
                "VERIFICATION", filepath, getMethodDescription(method), "FAILED", result.details);
            return result;
        }
    } else {
        result.is_verified = true;
        result.details = "Zero-byte file verified (empty payload).";
    }

    // 5. Shred metadata and unlink
    shredMetadataAndUnlink(filepath);

    // 6. Post-unlink accessibility check
    result.accessible_after_deletion = !verification::EraseVerification::verifyInaccessible(filepath);

    // 7. Record in audit trail
    logging::AuditLogger::getInstance().logEvent(
        "SECURE_FILE_ERASE",
        filepath,
        getMethodDescription(method),
        result.is_verified ? "SUCCESS" : "VERIFICATION_FAILED",
        result.details
    );

    return result;
}

} // namespace sanitization
} // namespace forensivault
