#pragma once

#include "carving/file_signature.hpp"
#include "carving/signature_scanner.hpp"
#include "carving/format_validator.hpp"
#include "core/disk_image_reader.hpp"
#include <string>
#include <vector>
#include <filesystem>
#include <functional>

namespace forensivault::carving {

/**
 * @brief Configuration parameters for carving session.
 */
struct CarverOptions {
    std::string outputDirectory{"recovered"};
    bool extractFiles{true};
    bool organizeByType{true};     // Creates subdirectories e.g. recovered/JPG/, recovered/PDF/
    bool validateIntegrity{true};  // Performs deep structural verification
    double minimumConfidence{20.0};// Minimum confidence score required to export
    uint64_t maxCarveSize{100ULL * 1024ULL * 1024ULL}; // 100 MB max per file
};

/**
 * @brief Summary report of a complete carving operation.
 */
struct CarvingSessionResult {
    std::string imagePath;
    uint64_t totalBytesScanned{0};
    uint64_t totalSectorsScanned{0};
    size_t signaturesDiscovered{0};
    size_t filesSuccessfullyCarved{0};
    size_t validFilesCount{0};
    size_t partialFilesCount{0};
    std::vector<CarvedFile> carvedFiles;
    double durationMilliseconds{0.0};
};

/**
 * @brief Main file carving engine for digital forensics.
 * Orchestrates scanning, boundary determination, structural validation,
 * cryptographic hashing, and non-destructive file extraction.
 */
class FileCarver {
public:
    explicit FileCarver(CarverOptions options = CarverOptions{});

    /**
     * @brief Execute full forensic carving against an opened disk image.
     * @param reader Read-only disk image handle.
     * @param progress Optional progress reporting callback.
     * @return Full carving session report.
     */
    CarvingSessionResult carve(core::DiskImageReader& reader,
                               ScanProgressCallback progress = nullptr);

    /**
     * @brief Carve and validate a single candidate file at a known offset.
     */
    std::optional<CarvedFile> carveSingle(core::DiskImageReader& reader,
                                          const SignatureMatch& match,
                                          uint64_t nextMatchOffset = 0);

private:
    std::string generateUniqueFilename(uint64_t id, 
                                       const std::string& ext, 
                                       const std::string& subfolder);

    CarverOptions options_;
    SignatureDatabase db_;
};

} // namespace forensivault::carving
