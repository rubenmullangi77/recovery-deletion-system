#pragma once

#include "sanitization/sanitization_types.hpp"
#include "sanitization/secure_file_eraser.hpp"
#include "sanitization/secure_folder_eraser.hpp"
#include <string>
#include <vector>

namespace forensivault {
namespace sanitization {

struct EraseOperationResult {
    bool success{false};
    std::string summary;
    size_t files_erased{0};
    size_t folders_erased{0};
    uint64_t total_bytes_erased{0};
    std::vector<std::string> errors;
    std::vector<VerificationResult> verifications;
    std::vector<std::string> limitations;
};

class EraseOperation {
public:
    explicit EraseOperation(SanitizationMethod method = SanitizationMethod::NIST_800_88_CLEAR);
    ~EraseOperation() = default;

    // Selection methods
    void addFile(const std::string& path);
    void addFolder(const std::string& path);
    void addBatch(const std::vector<std::string>& paths);
    void clearSelection();

    const std::vector<std::string>& getSelectedFiles() const { return selected_files_; }
    const std::vector<std::string>& getSelectedFolders() const { return selected_folders_; }

    // Configuration
    void setMethod(SanitizationMethod method) { method_ = method; }
    SanitizationMethod getMethod() const { return method_; }

    // Preview what will be processed before making destructive changes
    ErasePreview preview() const;

    // Explicit confirmation enforcement
    void setConfirmed(bool confirmed) { confirmed_ = confirmed; }
    bool isConfirmed() const { return confirmed_; }

    // Execute sanitization operation
    EraseOperationResult execute(ProgressCallback callback = nullptr);

    // Constant confirmation token string for automated or scripted confirmation
    static constexpr const char* CONFIRMATION_TOKEN = "CONFIRM_PERMANENT_ERASURE";
    bool setConfirmationToken(const std::string& token);

private:
    SanitizationMethod method_;
    std::vector<std::string> selected_files_;
    std::vector<std::string> selected_folders_;
    bool confirmed_{false};

    SecureFileEraser file_eraser_;
    SecureFolderEraser folder_eraser_;
};

} // namespace sanitization
} // namespace forensivault
