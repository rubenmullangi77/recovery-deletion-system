#include "sanitization/sanitization_verifier.hpp"
#include "forensivault/common/crypto_hash.hpp"
#include <fstream>
#include <vector>
#include <sstream>
#include <iomanip>

namespace forensivault {
namespace sanitization {

SanitizationVerificationResult SanitizationVerifier::verifyImage(
    const std::string& imagePath,
    const SanitizationStrategy& strategy,
    const std::string& preWipeHash) {

    SanitizationVerificationResult res;
    res.limitations = strategy.limitations(DriveMediaType::DISK_IMAGE_RAW);

    std::ifstream ifs(imagePath, std::ios::binary | std::ios::ate);
    if (!ifs) {
        res.verified = false;
        res.details = "Verification failed: Could not open image file for readback verification.";
        return res;
    }

    uint64_t fileSize = static_cast<uint64_t>(ifs.tellg());
    ifs.seekg(0, std::ios::beg);

    if (fileSize == 0) {
        res.verified = true;
        res.post_wipe_hash = CryptoHash::sha256("");
        res.details = "Verified: Zero-length image target.";
        return res;
    }

    CryptoHash::Sha256Context shaCtx;
    const size_t chunkSize = 64 * 1024;
    std::vector<uint8_t> buffer(chunkSize);

    uint64_t bytesProcessed = 0;
    uint64_t totalZeroBytes = 0;

    // We also take a representative sample for Shannon entropy calculation
    std::vector<uint8_t> entropySample;
    const size_t maxEntropySample = 1024 * 1024; // Up to 1 MB sample

    while (bytesProcessed < fileSize) {
        size_t toRead = static_cast<size_t>(std::min<uint64_t>(chunkSize, fileSize - bytesProcessed));
        ifs.read(reinterpret_cast<char*>(buffer.data()), toRead);
        size_t bytesRead = static_cast<size_t>(ifs.gcount());
        if (bytesRead == 0) break;

        shaCtx.update(buffer.data(), bytesRead);

        if (entropySample.size() < maxEntropySample) {
            size_t take = std::min(bytesRead, maxEntropySample - entropySample.size());
            entropySample.insert(entropySample.end(), buffer.begin(), buffer.begin() + take);
        }

        for (size_t i = 0; i < bytesRead; ++i) {
            if (buffer[i] == 0x00) totalZeroBytes++;
        }

        bytesProcessed += bytesRead;
    }
    ifs.close();

    res.post_wipe_hash = shaCtx.finalize();
    res.measured_entropy = CryptoHash::calculateEntropy(entropySample);

    std::ostringstream ss;

    // Pre vs Post hash check
    bool hashChanged = (!preWipeHash.empty() && preWipeHash != res.post_wipe_hash);
    if (!hashChanged && !preWipeHash.empty()) {
        res.verified = false;
        res.details = "Verification failed: Post-wipe hash is identical to pre-wipe hash (no data modified).";
        return res;
    }

    if (strategy.name().find("Clear") != std::string::npos || strategy.name().find("Zero") != std::string::npos) {
        res.match_rate_percentage = (static_cast<double>(totalZeroBytes) / bytesProcessed) * 100.0;
        res.verified = (res.match_rate_percentage >= 99.99 && res.measured_entropy < 0.05);

        ss << "Pattern Verification: " << std::fixed << std::setprecision(2) << res.match_rate_percentage << "% 0x00 match. "
           << "Entropy: " << std::setprecision(4) << res.measured_entropy << " bits/byte (Expected ~0.0). "
           << "Cryptographic Hash: Pre [" << (preWipeHash.empty() ? "N/A" : preWipeHash.substr(0, 8))
           << "...] -> Post [" << res.post_wipe_hash.substr(0, 8) << "...]. "
           << (res.verified ? "VERIFIED CLEAN." : "VERIFICATION FAILED.");
    } else {
        // Random / DoD 3-pass ending in random
        res.match_rate_percentage = 100.0;
        res.verified = (res.measured_entropy >= 7.2);

        ss << "Entropy Verification: " << std::fixed << std::setprecision(4) << res.measured_entropy << " bits/byte (Expected >7.2). "
           << "Cryptographic Hash: Pre [" << (preWipeHash.empty() ? "N/A" : preWipeHash.substr(0, 8))
           << "...] -> Post [" << res.post_wipe_hash.substr(0, 8) << "...]. "
           << (res.verified ? "VERIFIED RANDOMIZED." : "INSUFFICIENT ENTROPY.");
    }

    res.details = ss.str();
    return res;
}

} // namespace sanitization
} // namespace forensivault
