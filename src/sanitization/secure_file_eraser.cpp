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
#include <sstream>
#include <iomanip>
#include <cmath>

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
#include <sys/types.h>
#endif

namespace fs = std::filesystem;

namespace forensivault {
namespace sanitization {

namespace {

#if defined(_WIN32)
struct ScopedFileHandle {
    HANDLE handle{INVALID_HANDLE_VALUE};
    explicit ScopedFileHandle(HANDLE h = INVALID_HANDLE_VALUE) : handle(h) {}
    ~ScopedFileHandle() { close(); }
    ScopedFileHandle(const ScopedFileHandle&) = delete;
    ScopedFileHandle& operator=(const ScopedFileHandle&) = delete;
    HANDLE get() const { return handle; }
    bool isValid() const { return handle != INVALID_HANDLE_VALUE && handle != NULL; }
    void close() {
        if (isValid()) {
            CloseHandle(handle);
            handle = INVALID_HANDLE_VALUE;
        }
    }
};
#else
struct ScopedFileDescriptor {
    int fd{-1};
    explicit ScopedFileDescriptor(int f = -1) : fd(f) {}
    ~ScopedFileDescriptor() { close(); }
    ScopedFileDescriptor(const ScopedFileDescriptor&) = delete;
    ScopedFileDescriptor& operator=(const ScopedFileDescriptor&) = delete;
    int get() const { return fd; }
    bool isValid() const { return fd >= 0; }
    void close() {
        if (fd >= 0) {
            ::close(fd);
            fd = -1;
        }
    }
};
#endif

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

#if defined(_WIN32)
bool SecureFileEraser::overwritePayload(
    HANDLE hFile,
    uint64_t fileSize,
    SanitizationMethod method,
    ProgressCallback callback,
    const std::string& filepath) {

    int totalPasses = getPassCount(method);
    const size_t chunkSize = 64 * 1024;
    std::vector<uint8_t> buffer(chunkSize);

    for (int pass = 1; pass <= totalPasses; ++pass) {
        LARGE_INTEGER liZero{};
        if (!SetFilePointerEx(hFile, liZero, NULL, FILE_BEGIN)) {
            return false;
        }

        uint64_t bytesWrittenThisPass = 0;
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
                    return false;
                }
            } else {
                std::fill(buffer.begin(), buffer.begin() + toWrite, fixedByte);
            }

            size_t chunkWritten = 0;
            while (chunkWritten < toWrite) {
                DWORD written = 0;
                DWORD needed = static_cast<DWORD>(toWrite - chunkWritten);
                if (!WriteFile(hFile, buffer.data() + chunkWritten, needed, &written, NULL) || written == 0) {
                    return false;
                }
                chunkWritten += written;
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

        if (!FlushFileBuffers(hFile)) {
            return false;
        }
    }

    return true;
}

VerificationResult SecureFileEraser::verifyHandle(
    HANDLE hFile,
    uint64_t expectedSize,
    SanitizationMethod method,
    const std::string& preWipeSampleHash,
    const TargetIdentity& id) {

    VerificationResult res;
    res.limitations = getMethodLimitations(method);

    BY_HANDLE_FILE_INFORMATION bhfi{};
    if (!GetFileInformationByHandle(hFile, &bhfi)) {
        res.is_verified = false;
        res.details = "Verification failed: Unable to query handle information.";
        return res;
    }
    uint64_t currentSize = (static_cast<uint64_t>(bhfi.nFileSizeHigh) << 32) | bhfi.nFileSizeLow;
    if (currentSize != expectedSize) {
        res.is_verified = false;
        res.details = "Verification failed: Unexpected file size mutation during sanitization (" +
                      std::to_string(currentSize) + " != " + std::to_string(expectedSize) + ").";
        return res;
    }
    if (bhfi.nNumberOfLinks > 1) {
        res.is_verified = false;
        res.details = "Verification failed: Hard links created during sanitization.";
        return res;
    }
    if (bhfi.dwVolumeSerialNumber != id.volume_serial_number ||
        bhfi.nFileIndexHigh != id.file_index_high ||
        bhfi.nFileIndexLow != id.file_index_low) {
        res.is_verified = false;
        res.details = "Verification failed: Underlying filesystem object identity changed.";
        return res;
    }

    if (expectedSize == 0) {
        res.is_verified = true;
        res.match_rate_percentage = 100.0;
        res.measured_entropy = 0.0;
        res.details = "Verified zero-byte file.";
        return res;
    }

    LARGE_INTEGER liZero{};
    if (!SetFilePointerEx(hFile, liZero, NULL, FILE_BEGIN)) {
        res.is_verified = false;
        res.details = "Verification failed: Seek to beginning failed.";
        return res;
    }

    const size_t chunkSize = 64 * 1024;
    std::vector<uint8_t> buffer(chunkSize);
    uint64_t bytesProcessed = 0;
    uint64_t totalZeroBytes = 0;
    std::vector<uint8_t> entropySample;
    const size_t maxEntropySample = 1024 * 1024;
    std::string firstChunkHash;

    while (bytesProcessed < expectedSize) {
        size_t toRead = static_cast<size_t>(std::min<uint64_t>(chunkSize, expectedSize - bytesProcessed));
        DWORD bytesRead = 0;
        if (!ReadFile(hFile, buffer.data(), static_cast<DWORD>(toRead), &bytesRead, NULL) || bytesRead == 0) {
            break;
        }

        if (bytesProcessed == 0) {
            firstChunkHash = CryptoHash::sha256(buffer.data(), bytesRead);
        }

        if (entropySample.size() < maxEntropySample) {
            size_t take = std::min<size_t>(bytesRead, maxEntropySample - entropySample.size());
            entropySample.insert(entropySample.end(), buffer.begin(), buffer.begin() + take);
        }

        for (DWORD i = 0; i < bytesRead; ++i) {
            if (buffer[i] == 0x00) totalZeroBytes++;
        }

        bytesProcessed += bytesRead;
    }

    if (bytesProcessed < expectedSize) {
        res.is_verified = false;
        res.details = "Verification failed: Short read during readback (" +
                      std::to_string(bytesProcessed) + "/" + std::to_string(expectedSize) + " bytes).";
        return res;
    }

    res.measured_entropy = CryptoHash::calculateEntropy(entropySample);
    std::ostringstream details;

    if (method == SanitizationMethod::NIST_800_88_CLEAR ||
        method == SanitizationMethod::ZERO_FILL) {
        res.match_rate_percentage = (static_cast<double>(totalZeroBytes) / bytesProcessed) * 100.0;
        res.is_verified = (res.match_rate_percentage >= 99.99 && res.measured_entropy < 0.05);

        details << "Pattern verification (Zero-Fill across " << bytesProcessed << " bytes): "
                << std::fixed << std::setprecision(2) << res.match_rate_percentage << "% match (0x00). "
                << "Measured Entropy: " << std::setprecision(4) << res.measured_entropy << " bits/byte (Expected ~0.0). "
                << (res.is_verified ? "Passed." : "Failed.");
    } else if (method == SanitizationMethod::DOD_5220_22_M ||
               method == SanitizationMethod::PSEUDORANDOM_1_PASS) {
        if (!preWipeSampleHash.empty() && firstChunkHash == preWipeSampleHash) {
            res.is_verified = false;
            res.match_rate_percentage = 0.0;
            details << "Verification failed: Post-wipe content identical to pre-wipe content. File was not overwritten.";
        } else {
            double minEntropy = (entropySample.size() < 512)
                ? std::max(1.0, std::log2(static_cast<double>(std::max<size_t>(2, entropySample.size()))) * 0.70)
                : 7.2;

            res.is_verified = (res.measured_entropy >= minEntropy);
            res.match_rate_percentage = 100.0;

            details << "Pattern verification (Pseudorandom across " << bytesProcessed << " bytes): Measured Entropy: "
                    << std::fixed << std::setprecision(4) << res.measured_entropy << " bits/byte (Required > "
                    << std::setprecision(2) << minEntropy << "). "
                    << (res.is_verified ? "High entropy randomness verified." : "Entropy too low; possible incomplete overwrite.");
        }
    }

    res.details = details.str();
    return res;
}

bool SecureFileEraser::secureUnlink(
    HANDLE hFile,
    const TargetIdentity& id,
    const std::string& filepath) {

    if (!id.matchesPath(filepath)) {
        logging::AuditLogger::getInstance().logEvent(
            "PATH_REPLACEMENT_DETECTED", filepath, "SECURE_UNLINK", "FAILED",
            "Target path no longer matches open file handle identity; aborting unlink to prevent collateral destruction.");
        return false;
    }

    FILE_DISPOSITION_INFO fdi{};
    fdi.DeleteFile = TRUE;
    if (SetFileInformationByHandle(hFile, FileDispositionInfo, &fdi, sizeof(fdi))) {
        return true;
    }

    if (DeleteFileA(filepath.c_str())) {
        return true;
    }

    return false;
}

#else

bool SecureFileEraser::overwritePayload(
    int fd,
    uint64_t fileSize,
    SanitizationMethod method,
    ProgressCallback callback,
    const std::string& filepath) {

    int totalPasses = getPassCount(method);
    const size_t chunkSize = 64 * 1024;
    std::vector<uint8_t> buffer(chunkSize);

    for (int pass = 1; pass <= totalPasses; ++pass) {
        if (::lseek(fd, 0, SEEK_SET) == (off_t)-1) {
            return false;
        }

        uint64_t bytesWrittenThisPass = 0;
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
                    return false;
                }
            } else {
                std::fill(buffer.begin(), buffer.begin() + toWrite, fixedByte);
            }

            size_t chunkWritten = 0;
            while (chunkWritten < toWrite) {
                ssize_t w = ::write(fd, buffer.data() + chunkWritten, toWrite - chunkWritten);
                if (w > 0) {
                    chunkWritten += static_cast<size_t>(w);
                } else if (w < 0 && errno == EINTR) {
                    continue;
                } else {
                    return false;
                }
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

        if (fdatasync(fd) != 0 && fsync(fd) != 0) {
            return false;
        }
    }

    return true;
}

VerificationResult SecureFileEraser::verifyHandle(
    int fd,
    uint64_t expectedSize,
    SanitizationMethod method,
    const std::string& preWipeSampleHash,
    const TargetIdentity& id) {

    VerificationResult res;
    res.limitations = getMethodLimitations(method);

    struct stat st{};
    if (::fstat(fd, &st) != 0) {
        res.is_verified = false;
        res.details = "Verification failed: Unable to fstat descriptor.";
        return res;
    }
    if (static_cast<uint64_t>(st.st_size) != expectedSize) {
        res.is_verified = false;
        res.details = "Verification failed: Unexpected file size mutation during sanitization (" +
                      std::to_string(st.st_size) + " != " + std::to_string(expectedSize) + ").";
        return res;
    }
    if (st.st_nlink > 1) {
        res.is_verified = false;
        res.details = "Verification failed: Hard links created during sanitization.";
        return res;
    }
    if (static_cast<uint64_t>(st.st_dev) != id.device_id || static_cast<uint64_t>(st.st_ino) != id.inode_number) {
        res.is_verified = false;
        res.details = "Verification failed: Underlying filesystem object identity changed.";
        return res;
    }

    if (expectedSize == 0) {
        res.is_verified = true;
        res.match_rate_percentage = 100.0;
        res.measured_entropy = 0.0;
        res.details = "Verified zero-byte file.";
        return res;
    }

    if (::lseek(fd, 0, SEEK_SET) == (off_t)-1) {
        res.is_verified = false;
        res.details = "Verification failed: Seek to beginning failed.";
        return res;
    }

    const size_t chunkSize = 64 * 1024;
    std::vector<uint8_t> buffer(chunkSize);
    uint64_t bytesProcessed = 0;
    uint64_t totalZeroBytes = 0;
    std::vector<uint8_t> entropySample;
    const size_t maxEntropySample = 1024 * 1024;
    std::string firstChunkHash;

    while (bytesProcessed < expectedSize) {
        size_t toRead = static_cast<size_t>(std::min<uint64_t>(chunkSize, expectedSize - bytesProcessed));
        ssize_t bytesRead = ::read(fd, buffer.data(), toRead);
        if (bytesRead < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (bytesRead == 0) break;

        if (bytesProcessed == 0) {
            firstChunkHash = CryptoHash::sha256(buffer.data(), static_cast<size_t>(bytesRead));
        }

        if (entropySample.size() < maxEntropySample) {
            size_t take = std::min<size_t>(static_cast<size_t>(bytesRead), maxEntropySample - entropySample.size());
            entropySample.insert(entropySample.end(), buffer.begin(), buffer.begin() + take);
        }

        for (ssize_t i = 0; i < bytesRead; ++i) {
            if (buffer[i] == 0x00) totalZeroBytes++;
        }

        bytesProcessed += static_cast<uint64_t>(bytesRead);
    }

    if (bytesProcessed < expectedSize) {
        res.is_verified = false;
        res.details = "Verification failed: Short read during readback (" +
                      std::to_string(bytesProcessed) + "/" + std::to_string(expectedSize) + " bytes).";
        return res;
    }

    res.measured_entropy = CryptoHash::calculateEntropy(entropySample);
    std::ostringstream details;

    if (method == SanitizationMethod::NIST_800_88_CLEAR ||
        method == SanitizationMethod::ZERO_FILL) {
        res.match_rate_percentage = (static_cast<double>(totalZeroBytes) / bytesProcessed) * 100.0;
        res.is_verified = (res.match_rate_percentage >= 99.99 && res.measured_entropy < 0.05);

        details << "Pattern verification (Zero-Fill across " << bytesProcessed << " bytes): "
                << std::fixed << std::setprecision(2) << res.match_rate_percentage << "% match (0x00). "
                << "Measured Entropy: " << std::setprecision(4) << res.measured_entropy << " bits/byte (Expected ~0.0). "
                << (res.is_verified ? "Passed." : "Failed.");
    } else if (method == SanitizationMethod::DOD_5220_22_M ||
               method == SanitizationMethod::PSEUDORANDOM_1_PASS) {
        if (!preWipeSampleHash.empty() && firstChunkHash == preWipeSampleHash) {
            res.is_verified = false;
            res.match_rate_percentage = 0.0;
            details << "Verification failed: Post-wipe content identical to pre-wipe content. File was not overwritten.";
        } else {
            double minEntropy = (entropySample.size() < 512)
                ? std::max(1.0, std::log2(static_cast<double>(std::max<size_t>(2, entropySample.size()))) * 0.70)
                : 7.2;

            res.is_verified = (res.measured_entropy >= minEntropy);
            res.match_rate_percentage = 100.0;

            details << "Pattern verification (Pseudorandom across " << bytesProcessed << " bytes): Measured Entropy: "
                    << std::fixed << std::setprecision(4) << res.measured_entropy << " bits/byte (Required > "
                    << std::setprecision(2) << minEntropy << "). "
                    << (res.is_verified ? "High entropy randomness verified." : "Entropy too low; possible incomplete overwrite.");
        }
    }

    res.details = details.str();
    return res;
}

bool SecureFileEraser::secureUnlink(
    int fd,
    const TargetIdentity& id,
    const std::string& filepath) {

    if (!id.matchesPath(filepath)) {
        logging::AuditLogger::getInstance().logEvent(
            "PATH_REPLACEMENT_DETECTED", filepath, "SECURE_UNLINK", "FAILED",
            "Target path no longer matches open file descriptor identity; aborting unlink to prevent collateral destruction.");
        return false;
    }

    fs::path p(filepath);
    fs::path parent = p.parent_path();
    std::string filename = p.filename().string();
    if (parent.empty()) parent = ".";

    int dirfd = ::open(parent.string().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0) {
        logging::AuditLogger::getInstance().logEvent(
            "PARENT_DIR_OPEN_FAILED", filepath, "SECURE_UNLINK", "FAILED",
            "Unable to open parent directory securely with O_NOFOLLOW; aborting unlink.");
        return false;
    }

    struct stat st_entry{};
    if (::fstatat(dirfd, filename.c_str(), &st_entry, AT_SYMLINK_NOFOLLOW) != 0 ||
        S_ISLNK(st_entry.st_mode) || !S_ISREG(st_entry.st_mode) ||
        static_cast<uint64_t>(st_entry.st_dev) != id.device_id ||
        static_cast<uint64_t>(st_entry.st_ino) != id.inode_number ||
        st_entry.st_nlink != 1) {
        ::close(dirfd);
        logging::AuditLogger::getInstance().logEvent(
            "PATH_REPLACEMENT_DETECTED", filepath, "SECURE_UNLINK", "FAILED",
            "Directory entry verification in parent dir failed; aborting unlink.");
        return false;
    }

    int res = ::unlinkat(dirfd, filename.c_str(), 0);
    ::close(dirfd);
    if (res != 0) {
        return false;
    }

    struct stat st_after{};
    if (::fstat(fd, &st_after) == 0) {
        if (st_after.st_nlink != 0) {
            logging::AuditLogger::getInstance().logEvent(
                "UNLINK_RACE_DETECTED", filepath, "SECURE_UNLINK", "FAILED",
                "Unlink did not decrement target inode link count to zero; path replacement race occurred!");
            return false;
        }
    }

    return true;
}

#endif

VerificationResult SecureFileEraser::eraseFile(
    const std::string& filepath,
    SanitizationMethod method,
    ProgressCallback callback) {

    VerificationResult result;
    result.limitations = getMethodLimitations(method);

    // 1. Initial System Protection check on target path string
    std::string blockReason;
    if (SystemProtectionGuard::isProtected(filepath, blockReason)) {
        result.is_verified = false;
        result.details = "SECURITY INTERLOCK BLOCKED: " + blockReason;
        logging::AuditLogger::getInstance().logEvent(
            "SAFETY_BLOCK", filepath, getMethodDescription(method), "BLOCKED", result.details);
        return result;
    }

    // 2. Open the target EXACTLY ONCE with handle-binding
#if defined(_WIN32)
    HANDLE hRaw = CreateFileA(
        filepath.c_str(),
        GENERIC_READ | GENERIC_WRITE | DELETE,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT,
        NULL
    );
    if (hRaw == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED) {
        hRaw = CreateFileA(
            filepath.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            NULL
        );
    }
    if (hRaw == INVALID_HANDLE_VALUE) {
        result.is_verified = false;
        result.details = "Unable to open target file safely (reparse point, directory, or access denied).";
        return result;
    }
    ScopedFileHandle fileHandle(hRaw);
    HANDLE hFile = fileHandle.get();
#else
    int rawFd = ::open(filepath.c_str(), O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    if (rawFd < 0) {
        result.is_verified = false;
        result.details = "Unable to open target file safely (symlink, directory, or access denied).";
        return result;
    }
    ScopedFileDescriptor fileHandle(rawFd);
    int fd = fileHandle.get();
#endif

    // 3. Obtain identity immediately from the open handle/descriptor
#if defined(_WIN32)
    TargetIdentity id = captureIdentityFromHandle(hFile, filepath, TargetType::REGULAR_FILE);
    if (!id.valid || (id.file_attributes & FILE_ATTRIBUTE_DIRECTORY) || (id.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        result.is_verified = false;
        result.details = "Target is not a valid regular file.";
        return result;
    }
    if (id.number_of_links > 1) {
        result.is_verified = false;
        result.details = "Refusing to erase: target has multiple hard links (hard_link_count > 1).";
        return result;
    }
#else
    TargetIdentity id = captureIdentityFromFd(fd, filepath, TargetType::REGULAR_FILE);
    if (!id.valid || !S_ISREG(id.mode)) {
        result.is_verified = false;
        result.details = "Target is not a valid regular file.";
        return result;
    }
    if (id.hard_link_count > 1) {
        result.is_verified = false;
        result.details = "Refusing to erase: target has multiple hard links (hard_link_count > 1).";
        return result;
    }
#endif

    // Ensure actual descriptor path was resolved safely from the open handle
    if (!id.path_resolved_from_handle || id.canonical_path.empty()) {
        result.is_verified = false;
        result.details = "SECURITY INTERLOCK BLOCKED: Unable to reliably resolve actual descriptor path from open handle.";
        logging::AuditLogger::getInstance().logEvent(
            "SAFETY_BLOCK", filepath, getMethodDescription(method), "BLOCKED", result.details);
        return result;
    }

    // System Protection re-validation against handle-resolved canonical path
    if (SystemProtectionGuard::isProtected(id.canonical_path, blockReason)) {
        result.is_verified = false;
        result.details = "SECURITY INTERLOCK BLOCKED: " + blockReason;
        logging::AuditLogger::getInstance().logEvent(
            "SAFETY_BLOCK", id.canonical_path, getMethodDescription(method), "BLOCKED", result.details);
        return result;
    }

    uint64_t fileSize = id.size_bytes;

    // 4. Pre-hashing through the SAME descriptor/handle
    std::string preWipeSampleHash;
    if (fileSize > 0) {
#if defined(_WIN32)
        LARGE_INTEGER liZero{};
        if (SetFilePointerEx(hFile, liZero, NULL, FILE_BEGIN)) {
            const size_t probeLen = static_cast<size_t>(std::min<uint64_t>(fileSize, 64 * 1024));
            std::vector<uint8_t> pBuf(probeLen);
            DWORD bytesRead = 0;
            if (ReadFile(hFile, pBuf.data(), static_cast<DWORD>(probeLen), &bytesRead, NULL) && bytesRead > 0) {
                preWipeSampleHash = forensivault::CryptoHash::sha256(pBuf.data(), bytesRead);
            }
        }
#else
        if (::lseek(fd, 0, SEEK_SET) != (off_t)-1) {
            const size_t probeLen = static_cast<size_t>(std::min<uint64_t>(fileSize, 64 * 1024));
            std::vector<uint8_t> pBuf(probeLen);
            size_t totalRead = 0;
            while (totalRead < probeLen) {
                ssize_t r = ::read(fd, pBuf.data() + totalRead, probeLen - totalRead);
                if (r > 0) totalRead += static_cast<size_t>(r);
                else if (r < 0 && errno == EINTR) continue;
                else break;
            }
            if (totalRead > 0) {
                preWipeSampleHash = forensivault::CryptoHash::sha256(pBuf.data(), totalRead);
            }
        }
#endif
    }

    // 5. Multi-pass overwrite through the SAME descriptor/handle
    if (fileSize > 0) {
#if defined(_WIN32)
        if (!overwritePayload(hFile, fileSize, method, callback, filepath)) {
            result.is_verified = false;
            result.details = "Overwrite failed: IO error or hardware flush failure.";
            logging::AuditLogger::getInstance().logEvent(
                "SECURE_FILE_ERASE", filepath, getMethodDescription(method), "FAILED", result.details);
            return result;
        }
        // 6. Pre-unlink verification through the SAME descriptor/handle
        result = verifyHandle(hFile, fileSize, method, preWipeSampleHash, id);
        if (!result.is_verified) {
            logging::AuditLogger::getInstance().logEvent(
                "VERIFICATION", filepath, getMethodDescription(method), "FAILED", result.details);
            return result;
        }
#else
        if (!overwritePayload(fd, fileSize, method, callback, filepath)) {
            result.is_verified = false;
            result.details = "Overwrite failed: IO error or hardware flush failure.";
            logging::AuditLogger::getInstance().logEvent(
                "SECURE_FILE_ERASE", filepath, getMethodDescription(method), "FAILED", result.details);
            return result;
        }
        // 6. Pre-unlink verification through the SAME descriptor/handle
        result = verifyHandle(fd, fileSize, method, preWipeSampleHash, id);
        if (!result.is_verified) {
            logging::AuditLogger::getInstance().logEvent(
                "VERIFICATION", filepath, getMethodDescription(method), "FAILED", result.details);
            return result;
        }
#endif
    } else {
        // Zero-byte file: flush descriptor/handle
#if defined(_WIN32)
        FlushFileBuffers(hFile);
#else
        if (fdatasync(fd) != 0 && fsync(fd) != 0) {
            // ignore if fs doesn't support sync on 0-byte
        }
#endif
        result.is_verified = true;
        result.details = "Zero-byte file verified (empty payload).";
    }

    // 7. Metadata destruction through the SAME descriptor/handle (truncate to 0)
#if defined(_WIN32)
    LARGE_INTEGER liZero{};
    if (SetFilePointerEx(hFile, liZero, NULL, FILE_BEGIN)) {
        if (!SetEndOfFile(hFile)) {
            result.is_verified = false;
            result.details = "Metadata destruction failed: SetEndOfFile error: " + std::to_string(GetLastError());
            logging::AuditLogger::getInstance().logEvent(
                "SECURE_FILE_ERASE", filepath, getMethodDescription(method), "FAILED", result.details);
            return result;
        }
        FlushFileBuffers(hFile);
    } else {
        result.is_verified = false;
        result.details = "Metadata destruction failed: SetFilePointerEx error: " + std::to_string(GetLastError());
        logging::AuditLogger::getInstance().logEvent(
            "SECURE_FILE_ERASE", filepath, getMethodDescription(method), "FAILED", result.details);
        return result;
    }
#else
    if (::ftruncate(fd, 0) != 0) {
        result.is_verified = false;
        result.details = "Metadata destruction failed: ftruncate error: " + std::string(strerror(errno));
        logging::AuditLogger::getInstance().logEvent(
            "SECURE_FILE_ERASE", filepath, getMethodDescription(method), "FAILED", result.details);
        return result;
    }
    if (fdatasync(fd) != 0 && fsync(fd) != 0) {
        // flush after truncation
    }
#endif

    // 8. Secure final unlink with path replacement verification
#if defined(_WIN32)
    bool unlinked = secureUnlink(hFile, id, filepath);
#else
    bool unlinked = secureUnlink(fd, id, filepath);
#endif

    // Close handle before post-deletion accessibility verification
    fileHandle.close();

    if (!unlinked) {
        result.is_verified = false;
        result.details = "Security invariant violated: target path no longer matches open file handle or unlink failed.";
        logging::AuditLogger::getInstance().logEvent(
            "SECURE_FILE_ERASE", filepath, getMethodDescription(method), "FAILED", result.details);
        return result;
    }

    // 9. Post-unlink accessibility check
    result.accessible_after_deletion = !verification::EraseVerification::verifyInaccessible(filepath);

    // 10. Record in audit trail
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
