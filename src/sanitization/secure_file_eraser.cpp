#include "sanitization/secure_file_eraser.hpp"
#include "sanitization/system_protection.hpp"
#include "logging/audit_logger.hpp"
#include "forensivault/core/platform.hpp"
#include "forensivault/common/crypto_hash.hpp"
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
    std::string s;
    s.resize(length);
    std::vector<uint8_t> randBuf(length);
    if (core::Platform::getRandomBytes(randBuf.data(), length)) {
        for (size_t i = 0; i < length; ++i) {
            s[i] = charset[randBuf[i] % (sizeof(charset) - 1)];
        }
    } else {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        std::uniform_int_distribution<size_t> dist(0, sizeof(charset) - 2);
        for (size_t i = 0; i < length; ++i) {
            s[i] = charset[dist(gen)];
        }
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

#if defined(_WIN32)
    HANDLE hFile = CreateFileA(
        filepath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }

    BY_HANDLE_FILE_INFORMATION bhfi{};
    if (!GetFileInformationByHandle(hFile, &bhfi) ||
        (bhfi.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        (bhfi.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
        CloseHandle(hFile);
        return false;
    }
#else
    // Open once with O_NOFOLLOW to block symlink redirection; verify descriptor is regular file
    int fd = ::open(filepath.c_str(), O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }

    struct stat st{};
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        ::close(fd);
        return false;
    }
#endif

    for (int pass = 1; pass <= totalPasses; ++pass) {
#if defined(_WIN32)
        if (SetFilePointer(hFile, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
            CloseHandle(hFile);
            return false;
        }
#else
        if (::lseek(fd, 0, SEEK_SET) == (off_t)-1) {
            ::close(fd);
            return false;
        }
#endif
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
                if (!core::Platform::getRandomBytes(buffer.data(), toWrite)) {
#if defined(_WIN32)
                    CloseHandle(hFile);
#else
                    ::close(fd);
#endif
                    return false;
                }
            } else {
                std::fill(buffer.begin(), buffer.begin() + toWrite, fixedByte);
            }

#if defined(_WIN32)
            DWORD written = 0;
            if (!WriteFile(hFile, buffer.data(), static_cast<DWORD>(toWrite), &written, NULL) || written != toWrite) {
                CloseHandle(hFile);
                return false;
            }
#else
            size_t writtenTotal = 0;
            while (writtenTotal < toWrite) {
                ssize_t w = ::write(fd, buffer.data() + writtenTotal, toWrite - writtenTotal);
                if (w > 0) {
                    writtenTotal += static_cast<size_t>(w);
                } else if (w < 0 && errno == EINTR) {
                    continue;
                } else {
                    ::close(fd);
                    return false;
                }
            }
#endif

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

        // Durable hardware cache flush directly on active handle; flush failure is fatal
#if defined(_WIN32)
        if (!FlushFileBuffers(hFile)) {
            CloseHandle(hFile);
            return false;
        }
#else
        if (fdatasync(fd) != 0 && fsync(fd) != 0) {
            ::close(fd);
            return false;
        }
#endif
    }

#if defined(_WIN32)
    CloseHandle(hFile);
#else
    ::close(fd);
#endif
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
        std::string preWipeSampleHash;
        {
            std::ifstream preIfs(filepath, std::ios::binary);
            if (preIfs) {
                const size_t probeLen = static_cast<size_t>(std::min<uint64_t>(fileSize, 64 * 1024));
                std::vector<uint8_t> pBuf(probeLen);
                preIfs.read(reinterpret_cast<char*>(pBuf.data()), probeLen);
                preWipeSampleHash = forensivault::CryptoHash::sha256(pBuf.data(), static_cast<size_t>(preIfs.gcount()));
            }
        }

        if (!overwritePayload(filepath, fileSize, method, callback)) {
            result.is_verified = false;
            result.details = "Overwrite failed: IO error writing sectors.";
            logging::AuditLogger::getInstance().logEvent(
                "SECURE_FILE_ERASE", filepath, getMethodDescription(method), "FAILED", result.details);
            return result;
        }

        // 4. Pre-unlink verification
        result = verification::EraseVerification::verifyOverwrittenFile(filepath, method, fileSize, preWipeSampleHash);
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
