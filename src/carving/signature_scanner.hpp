#pragma once

#include "carving/file_signature.hpp"
#include "core/disk_image_reader.hpp"
#include <vector>
#include <string>
#include <functional>

namespace forensivault::carving {

/**
 * @brief Candidate match identified during sequential image scanning.
 */
struct SignatureMatch {
    uint64_t offset{0};
    uint64_t sector{0};
    const FileSignature* signature{nullptr};
};

/**
 * @brief Progress callback type for carving operations.
 */
using ScanProgressCallback = std::function<void(uint64_t bytesProcessed, uint64_t totalBytes, size_t matchesFound)>;

/**
 * @brief High-speed sequential signature scanner.
 * Scans disk images in chunked blocks, identifying potential file signatures
 * without loading the entire disk image into RAM.
 */
class SignatureScanner {
public:
    explicit SignatureScanner(const SignatureDatabase& db = SignatureDatabase::getInstance());

    /**
     * @brief Scan an opened DiskImageReader sequentially for known file signatures.
     * @param reader Read-only disk image handle.
     * @param callback Optional progress reporting callback.
     * @param chunkSize Size of stream read buffer (defaults to 1 MB).
     * @return Vector of discovered signature matches.
     */
    std::vector<SignatureMatch> scan(core::DiskImageReader& reader,
                                     ScanProgressCallback callback = nullptr,
                                     size_t chunkSize = 1024 * 1024);

private:
    const SignatureDatabase& db_;
};

} // namespace forensivault::carving
