#include "sanitization/image_sanitizer.hpp"
#include "sanitization/system_protection.hpp"
#include "logging/audit_logger.hpp"
#include "forensivault/common/crypto_hash.hpp"
#include <fstream>
#include <filesystem>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace fs = std::filesystem;

namespace forensivault {
namespace sanitization {

std::string ImageSanitizer::currentTimestampIso() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    std::tm tmBuf{};
#if defined(_WIN32)
    gmtime_s(&tmBuf, &now_c);
#else
    gmtime_r(&now_c, &tmBuf);
#endif

    std::ostringstream ss;
    ss << std::put_time(&tmBuf, "%Y-%m-%dT%H:%M:%S")
       << "." << std::setfill('0') << std::setw(3) << ms.count() << "Z";
    return ss.str();
}

std::string ImageSanitizer::computeImageSha256(const std::string& imagePath) {
    std::ifstream ifs(imagePath, std::ios::binary);
    if (!ifs) return "";

    CryptoHash::Sha256Context shaCtx;
    const size_t chunkSize = 64 * 1024;
    std::vector<uint8_t> buffer(chunkSize);

    while (ifs) {
        ifs.read(reinterpret_cast<char*>(buffer.data()), chunkSize);
        size_t bytesRead = static_cast<size_t>(ifs.gcount());
        if (bytesRead == 0) break;
        shaCtx.update(buffer.data(), bytesRead);
    }
    return shaCtx.finalize();
}

SanitizationReport ImageSanitizer::sanitizeImage(
    const std::string& imagePath,
    const SanitizationStrategy& strategy,
    bool confirmed,
    ProgressCallback callback) {

    SanitizationReport report;
    report.target_path = imagePath;
    report.strategy_name = strategy.name();
    report.strategy_standard = strategy.standard();
    report.media_type = DriveMediaType::DISK_IMAGE_RAW;
    report.limitations_disclosed = strategy.limitations(DriveMediaType::DISK_IMAGE_RAW);

    // 1. Safety Check: Verify target is a valid non-system disk image
    std::string blockReason;
    if (SystemProtectionGuard::isProtected(imagePath, blockReason) || imagePath.rfind("\\\\.\\", 0) == 0) {
        report.verified = false;
        report.summary = "ABORTED: Safety Interlock Blocked Target: " + (blockReason.empty() ? "Physical drive access prohibited" : blockReason);
        logging::AuditLogger::getInstance().logEvent(
            "SAFETY_BLOCK", imagePath, strategy.name(), "BLOCKED", report.summary);
        return report;
    }

    std::error_code ec;
    if (!fs::exists(imagePath, ec) || !fs::is_regular_file(imagePath, ec)) {
        report.verified = false;
        report.summary = "ABORTED: Image target does not exist or is not a regular file.";
        return report;
    }

    uint64_t imageSize = fs::file_size(imagePath, ec);
    if (ec || imageSize == 0) {
        report.verified = false;
        report.summary = "ABORTED: Target image has zero length or inaccessible size.";
        return report;
    }
    report.total_bytes_sanitized = imageSize;

    // 2. Mandatory Explicit Confirmation Check
    if (!confirmed) {
        report.verified = false;
        report.summary = "ABORTED: Explicit user confirmation required prior to destructive drive sanitization.";
        logging::AuditLogger::getInstance().logEvent(
            "DRIVE_SANITIZE", imagePath, strategy.name(), "CONFIRMATION_REQUIRED", report.summary);
        return report;
    }

    // 3. Compute Pre-Wipe Cryptographic Hash
    report.start_timestamp_iso = currentTimestampIso();
    auto startClock = std::chrono::steady_clock::now();
    report.pre_wipe_sha256 = computeImageSha256(imagePath);

    // 4. Multi-Pass Execution
    int totalPasses = strategy.totalPasses();
    const size_t chunkSize = 64 * 1024;
    std::vector<uint8_t> buffer(chunkSize);

    std::fstream file(imagePath, std::ios::in | std::ios::out | std::ios::binary);
    if (!file) {
        report.verified = false;
        report.summary = "IO ERROR: Unable to open image with write permissions.";
        logging::AuditLogger::getInstance().logEvent(
            "DRIVE_SANITIZE", imagePath, strategy.name(), "IO_ERROR", report.summary);
        return report;
    }

    for (int pass = 1; pass <= totalPasses; ++pass) {
        file.seekp(0, std::ios::beg);
        uint64_t bytesWrittenThisPass = 0;

        while (bytesWrittenThisPass < imageSize) {
            size_t toWrite = static_cast<size_t>(std::min<uint64_t>(chunkSize, imageSize - bytesWrittenThisPass));
            strategy.fillPassBuffer(pass, buffer.data(), toWrite);

            file.write(reinterpret_cast<const char*>(buffer.data()), toWrite);
            if (!file) {
                file.close();
                report.verified = false;
                report.summary = "IO ERROR: Write failed at offset " + std::to_string(bytesWrittenThisPass);
                return report;
            }

            bytesWrittenThisPass += toWrite;

            if (callback) {
                EraseProgress prog;
                prog.current_file = imagePath;
                prog.current_file_index = 1;
                prog.total_files = 1;
                prog.current_pass = pass;
                prog.total_passes = totalPasses;
                prog.bytes_processed_file = bytesWrittenThisPass;
                prog.file_size_bytes = imageSize;
                prog.total_bytes_processed = (static_cast<uint64_t>(pass - 1) * imageSize) + bytesWrittenThisPass;
                prog.total_bytes_all = static_cast<uint64_t>(totalPasses) * imageSize;
                prog.percentage = (static_cast<double>(prog.total_bytes_processed) / prog.total_bytes_all) * 100.0;
                callback(prog);
            }
        }

        file.flush();
        report.passes_completed++;
    }
    file.close();

    // 5. Post-Wipe Verification & Post-Hash Computation
    auto verifyRes = SanitizationVerifier::verifyImage(imagePath, strategy, report.pre_wipe_sha256);
    report.verified = verifyRes.verified;
    report.post_wipe_sha256 = verifyRes.post_wipe_hash;
    report.measured_entropy = verifyRes.measured_entropy;
    report.match_rate_percentage = verifyRes.match_rate_percentage;

    // 6. Record End Timestamp & Duration
    auto endClock = std::chrono::steady_clock::now();
    report.end_timestamp_iso = currentTimestampIso();
    report.duration_milliseconds = std::chrono::duration<double, std::milli>(endClock - startClock).count();

    std::ostringstream ss;
    ss << (report.verified ? "SUCCESS: " : "FAILED: ")
       << "Sanitized " << imageSize << " bytes across " << totalPasses << " pass(es) using "
       << strategy.name() << ". " << verifyRes.details;
    report.summary = ss.str();

    // 7. Audit Logging
    auto auditEntry = logging::AuditLogger::getInstance().logEvent(
        "DRIVE_SANITIZE",
        imagePath,
        strategy.name(),
        report.verified ? "SUCCESS" : "FAILED",
        "Pre-SHA256: " + report.pre_wipe_sha256 + " -> Post-SHA256: " + report.post_wipe_sha256 +
            " | Entropy: " + std::to_string(report.measured_entropy) + " | Duration: " +
            std::to_string(static_cast<int>(report.duration_milliseconds)) + " ms"
    );
    report.audit_entry_id = auditEntry.entry_id;
    report.audit_entry_hash = auditEntry.entry_hash;

    return report;
}

} // namespace sanitization
} // namespace forensivault
