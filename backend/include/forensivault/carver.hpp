#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <functional>

namespace forensivault::api {

struct CarvedFileItem {
    std::string fileType;
    uint64_t offset = 0;
    uint64_t lengthBytes = 0;
    bool isValid = false;
    double confidenceScore = 0.0;
    std::string recoveredFilePath;
    std::string sha256;
    std::string validationDetails;
};

struct CarveProgress {
    uint64_t bytesScanned = 0;
    uint64_t totalBytes = 0;
    double percentComplete = 0.0;
    size_t filesDiscovered = 0;
};

using CarveProgressCallback = std::function<void(const CarveProgress& progress)>;

struct CarveSessionResult {
    bool success = false;
    std::string sourcePath;
    std::string outputDirectory;
    uint64_t evidenceSizeBytes = 0;
    std::string evidenceSha256;
    size_t signaturesDiscovered = 0;
    size_t filesSuccessfullyCarved = 0;
    size_t validFilesCount = 0;
    double durationSeconds = 0.0;
    std::vector<CarvedFileItem> carvedFiles;
    std::string errorMessage;
};

/**
 * @brief Public high-level C++ API for forensic read-only deep file carving.
 */
class CarverAPI {
public:
    /**
     * @brief Performs signature scanning and file carving on a raw disk image or unmounted drive.
     * @param imagePath Path to the raw image file or device.
     * @param outputDirectory Path to store carved and validated files.
     * @param minConfidence Minimum confidence threshold (0.0 to 100.0) for extraction.
     * @param cb Optional callback for live progress updates.
     */
    static CarveSessionResult carve(const std::string& imagePath,
                                    const std::string& outputDirectory,
                                    double minConfidence = 30.0,
                                    CarveProgressCallback cb = nullptr);
};

} // namespace forensivault::api
