#include "carving/signature_scanner.hpp"
#include "core/binary_utils.hpp"
#include <algorithm>
#include <iostream>

namespace forensivault::carving {

SignatureScanner::SignatureScanner(const SignatureDatabase& db)
    : db_(db) {}

std::vector<SignatureMatch> SignatureScanner::scan(core::DiskImageReader& reader,
                                                 ScanProgressCallback callback,
                                                 size_t chunkSize) {
    std::vector<SignatureMatch> matches;
    if (!reader.isOpen() || reader.size() == 0) {
        return matches;
    }

    const uint64_t totalBytes = reader.size();
    if (chunkSize < 4096) chunkSize = 4096;

    // Determine the maximum header size across all signatures for overlap
    size_t maxHeaderSize = 16;
    for (const auto& sig : db_.getSignatures()) {
        if (sig.header.size() > maxHeaderSize) {
            maxHeaderSize = sig.header.size();
        }
    }

    std::vector<uint8_t> buffer(chunkSize + maxHeaderSize);
    uint64_t currentOffset = 0;

    while (currentOffset < totalBytes) {
        size_t bytesToRead = static_cast<size_t>(std::min<uint64_t>(chunkSize + maxHeaderSize, totalBytes - currentOffset));
        if (!reader.read(currentOffset, buffer.data(), bytesToRead)) {
            break;
        }

        // Scan through bytesToRead
        // To avoid missing headers split across chunks, scan up to (bytesToRead - maxHeaderSize) unless at EOF
        size_t scanLimit = (currentOffset + bytesToRead >= totalBytes) ? bytesToRead : (bytesToRead - maxHeaderSize);

        for (size_t i = 0; i < scanLimit; ++i) {
            const uint8_t* ptr = buffer.data() + i;
            size_t remainingInChunk = bytesToRead - i;

            auto matchedSigs = db_.matchHeader(ptr, remainingInChunk);
            if (!matchedSigs.empty()) {
                uint64_t absoluteOffset = currentOffset + i;
                uint64_t sector = core::BinaryUtils::byteToSector(absoluteOffset, reader.sectorSize());

                // Pick the highest priority match
                const FileSignature* bestSig = matchedSigs.front();
                matches.push_back({absoluteOffset, sector, bestSig});
            }
        }

        currentOffset += scanLimit;

        if (callback) {
            callback(currentOffset, totalBytes, matches.size());
        }
    }

    return matches;
}

} // namespace forensivault::carving
