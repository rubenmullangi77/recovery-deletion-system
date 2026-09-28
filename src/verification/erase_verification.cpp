#include "verification/erase_verification.hpp"
#include "forensivault/common/crypto_hash.hpp"
#include <fstream>
#include <filesystem>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <algorithm>

namespace fs = std::filesystem;

namespace forensivault {
namespace verification {

sanitization::VerificationResult EraseVerification::verifyOverwrittenFile(
    const std::string& filepath,
    sanitization::SanitizationMethod method,
    uint64_t expectedSize,
    const std::string& preWipeSampleHash) {

    sanitization::VerificationResult res;
    res.limitations = sanitization::getMethodLimitations(method);

    std::ifstream ifs(filepath, std::ios::binary);
    if (!ifs) {
        res.is_verified = false;
        res.details = "Verification failed: Unable to open file for readback verification.";
        return res;
    }

    if (expectedSize == 0) {
        res.is_verified = true;
        res.match_rate_percentage = 100.0;
        res.measured_entropy = 0.0;
        res.details = "Verified zero-byte file.";
        return res;
    }

    const size_t chunkSize = 64 * 1024;
    std::vector<uint8_t> buffer(chunkSize);
    uint64_t bytesProcessed = 0;
    uint64_t totalZeroBytes = 0;

    std::vector<uint8_t> entropySample;
    const size_t maxEntropySample = 1024 * 1024; // Up to 1 MB cumulative representative sample

    std::string firstChunkHash;

    while (bytesProcessed < expectedSize && ifs) {
        size_t toRead = static_cast<size_t>(std::min<uint64_t>(chunkSize, expectedSize - bytesProcessed));
        ifs.read(reinterpret_cast<char*>(buffer.data()), toRead);
        size_t bytesRead = static_cast<size_t>(ifs.gcount());
        if (bytesRead == 0) break;

        if (bytesProcessed == 0) {
            firstChunkHash = CryptoHash::sha256(buffer.data(), bytesRead);
        }

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

    if (bytesProcessed < expectedSize) {
        res.is_verified = false;
        res.details = "Verification failed: Short read (" + std::to_string(bytesProcessed) + "/" + std::to_string(expectedSize) + " bytes).";
        return res;
    }

    // Calculate Shannon Entropy on accumulated whole-file sample
    res.measured_entropy = CryptoHash::calculateEntropy(entropySample);

    std::ostringstream details;

    if (method == sanitization::SanitizationMethod::NIST_800_88_CLEAR ||
        method == sanitization::SanitizationMethod::ZERO_FILL) {
        res.match_rate_percentage = (static_cast<double>(totalZeroBytes) / bytesProcessed) * 100.0;
        res.is_verified = (res.match_rate_percentage >= 99.99 && res.measured_entropy < 0.05);

        details << "Pattern verification (Zero-Fill across " << bytesProcessed << " bytes): "
                << std::fixed << std::setprecision(2) << res.match_rate_percentage << "% match (0x00). "
                << "Measured Entropy: " << std::setprecision(4) << res.measured_entropy << " bits/byte (Expected ~0.0). "
                << (res.is_verified ? "Passed." : "Failed.");

    } else if (method == sanitization::SanitizationMethod::DOD_5220_22_M ||
               method == sanitization::SanitizationMethod::PSEUDORANDOM_1_PASS) {
        if (!preWipeSampleHash.empty() && firstChunkHash == preWipeSampleHash) {
            res.is_verified = false;
            res.match_rate_percentage = 0.0;
            details << "Verification failed: Post-wipe content identical to pre-wipe content. File was not overwritten despite high entropy.";
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

bool EraseVerification::verifyInaccessible(const std::string& filepath) {
    try {
        if (fs::exists(filepath)) {
            return false;
        }
    } catch (...) {
        // If filesystem error checking existence, proceed to open check
    }

    std::ifstream testOpen(filepath, std::ios::binary);
    if (testOpen.is_open()) {
        testOpen.close();
        return false;
    }

    return true;
}

} // namespace verification
} // namespace forensivault
