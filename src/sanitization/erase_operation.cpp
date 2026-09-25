#include "sanitization/erase_operation.hpp"
#include "sanitization/system_protection.hpp"
#include "logging/audit_logger.hpp"
#include <filesystem>
#include <sstream>

namespace fs = std::filesystem;

namespace forensivault {
namespace sanitization {

EraseOperation::EraseOperation(SanitizationMethod method)
    : method_(method) {}

void EraseOperation::addFile(const std::string& path) {
    selected_files_.push_back(path);
}

void EraseOperation::addFolder(const std::string& path) {
    selected_folders_.push_back(path);
}

void EraseOperation::addBatch(const std::vector<std::string>& paths) {
    for (const auto& p : paths) {
        std::error_code ec;
        if (fs::is_directory(p, ec)) {
            selected_folders_.push_back(p);
        } else {
            selected_files_.push_back(p);
        }
    }
}

void EraseOperation::clearSelection() {
    selected_files_.clear();
    selected_folders_.clear();
    confirmed_ = false;
}

bool EraseOperation::setConfirmationToken(const std::string& token) {
    if (token == CONFIRMATION_TOKEN) {
        confirmed_ = true;
        return true;
    }
    return false;
}

ErasePreview EraseOperation::preview() const {
    ErasePreview prev;
    prev.method = method_;
    prev.method_name = [this]() {
        std::ostringstream ss;
        ss << method_;
        return ss.str();
    }();
    prev.method_description = getMethodDescription(method_);
    prev.limitations = getMethodLimitations(method_);
    prev.safety_passed = true;

    // Inspect individual files
    for (const auto& f : selected_files_) {
        EraseItem item;
        item.path = f;
        item.is_directory = false;

        std::string blockReason;
        if (SystemProtectionGuard::isProtected(f, blockReason)) {
            item.status = EraseStatus::BLOCKED_PROTECTED;
            item.error_message = blockReason;
            prev.warnings.push_back("BLOCKED: " + f + " (" + blockReason + ")");
            prev.safety_passed = false;
        } else {
            item.status = EraseStatus::PENDING;
            std::error_code ec;
            if (fs::exists(f, ec) && fs::is_regular_file(f, ec)) {
                item.size_bytes = fs::file_size(f, ec);
            }
        }

        prev.total_files++;
        prev.total_bytes += item.size_bytes;
        prev.items.push_back(item);
    }

    // Inspect folders recursively
    for (const auto& folder : selected_folders_) {
        EraseItem item;
        item.path = folder;
        item.is_directory = true;

        std::string blockReason;
        if (SystemProtectionGuard::isProtected(folder, blockReason)) {
            item.status = EraseStatus::BLOCKED_PROTECTED;
            item.error_message = blockReason;
            prev.warnings.push_back("BLOCKED: " + folder + " (" + blockReason + ")");
            prev.safety_passed = false;
            prev.items.push_back(item);
            continue;
        }

        item.status = EraseStatus::PENDING;
        prev.total_folders++;

        std::error_code ec;
        if (fs::exists(folder, ec) && fs::is_directory(folder, ec)) {
            for (const auto& entry : fs::recursive_directory_iterator(folder, fs::directory_options::skip_permission_denied, ec)) {
                if (entry.is_regular_file()) {
                    prev.total_files++;
                    prev.total_bytes += entry.file_size();
                } else if (entry.is_directory()) {
                    prev.total_folders++;
                }
            }
        }
        prev.items.push_back(item);
    }

    if (!prev.safety_passed) {
        prev.risk_level = "PROHIBITED";
    } else if (prev.total_bytes > 100ULL * 1024ULL * 1024ULL || prev.total_folders > 0) {
        prev.risk_level = "High";
    } else if (prev.total_files > 1) {
        prev.risk_level = "Medium";
    } else {
        prev.risk_level = "Low";
    }

    return prev;
}

EraseOperationResult EraseOperation::execute(ProgressCallback callback) {
    EraseOperationResult result;
    result.limitations = getMethodLimitations(method_);

    // 1. Mandatory Confirmation Check
    if (!confirmed_) {
        result.success = false;
        result.summary = "ABORTED: Explicit user confirmation required prior to destructive erasure.";
        result.errors.push_back("Missing confirmation token or confirmation flag.");
        logging::AuditLogger::getInstance().logEvent(
            "ERASE_OPERATION", "BATCH", getMethodDescription(method_), "CONFIRMATION_REQUIRED", result.summary);
        return result;
    }

    // 2. Safety Interlock Pre-Check
    auto prev = preview();
    if (!prev.safety_passed) {
        result.success = false;
        result.summary = "ABORTED: System protection interlocks triggered on one or more selected items.";
        result.errors = prev.warnings;
        logging::AuditLogger::getInstance().logEvent(
            "SAFETY_BLOCK", "BATCH", getMethodDescription(method_), "BLOCKED", result.summary);
        return result;
    }

    // 3. Process individual files
    for (const auto& f : selected_files_) {
        auto ver = file_eraser_.eraseFile(f, method_, callback);
        result.verifications.push_back(ver);
        if (ver.is_verified) {
            result.files_erased++;
        } else {
            result.errors.push_back("Failed to erase " + f + ": " + ver.details);
        }
    }

    // 4. Process folders
    for (const auto& folder : selected_folders_) {
        auto folderRep = folder_eraser_.eraseFolder(folder, method_, callback);
        result.files_erased += folderRep.files_erased;
        result.folders_erased += folderRep.folders_removed;
        result.total_bytes_erased += folderRep.total_bytes_erased;
        result.verifications.insert(result.verifications.end(),
                                     folderRep.file_verifications.begin(),
                                     folderRep.file_verifications.end());

        if (!folderRep.success) {
            result.errors.push_back("Folder erasure error on " + folder + ": " + folderRep.details);
        }
    }

    result.success = result.errors.empty();
    std::ostringstream ss;
    ss << (result.success ? "Successfully" : "Partially")
       << " executed sanitization using " << method_
       << ". Erased " << result.files_erased << " files and "
       << result.folders_erased << " folders.";
    result.summary = ss.str();

    logging::AuditLogger::getInstance().logEvent(
        "ERASE_OPERATION",
        "BATCH",
        getMethodDescription(method_),
        result.success ? "SUCCESS" : "PARTIAL",
        result.summary
    );

    return result;
}

} // namespace sanitization
} // namespace forensivault
