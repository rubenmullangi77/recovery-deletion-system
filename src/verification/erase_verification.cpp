#include "verification/erase_verification.hpp"
#include "forensivault/common/crypto_hash.hpp"
#include <fstream>
#include <filesystem>
#include <vector>
#include <sstream>
#include <iomanip>

namespace fs = std::filesystem;

namespace forensivault {
namespace verification {

sanitization::VerificationResult EraseVerification::verifyOverwrittenFile(
    const std::string& filepath,
    sanitization::SanitizationMethod method,
    uint64_t expectedSize) {

    sanitization::VerificationResult res;
    res.limitations = sanitization::getMethodLimitations(method);

    std::ifstream ifs(filepath, std::ios::binary);
    if (!ifs) {
        res.is_verified = false;
        res.details = "Verification failed: Unable to open file for readback verification.";
        return res;
    }

    // Read up to 8 MB sample for verification
    const size_t maxSample = 8 * 1024 * 1024;
    size_t toRead = static_cast<size_t>(std::min<uint64_t>(expectedSize, maxSample));

    std::vector<uint8_t> buffer(toRead);
    if (toRead > 0) {
        ifs.read(reinterpret_cast<char*>(buffer.data()), toRead);
        size_t bytesRead = static_cast<size_t>(ifs.gcount());
        buffer.resize(bytesRead);
    }
    ifs.close();

    if (buffer.empty() && expectedSize > 0) {
        res.is_verified = false;
        res.details = "Verification failed: Zero bytes read from file.";
        return res;
    }

    // Calculate Shannon Entropy (0.0 to 8.0)
    res.measured_entropy = CryptoHash::calculateEntropy(buffer);

    std::ostringstream details;

    if (method == sanitization::SanitizationMethod::NIST_800_88_CLEAR ||
        method == sanitization::SanitizationMethod::ZERO_FILL) {
        // Expected byte is 0x00
        size_t matchingBytes = 0;
        for (uint8_t b : buffer) {
            if (b == 0x00) matchingBytes++;
        }

        res.match_rate_percentage = buffer.empty() ? 100.0 : (static_cast<double>(matchingBytes) / buffer.size()) * 100.0;
        res.is_verified = (res.match_rate_percentage >= 99.99 && res.measured_entropy < 0.05);

        details << "Pattern verification (Zero-Fill): "
                << std::fixed << std::setprecision(2) << res.match_rate_percentage << "% match (0x00). "
                << "Measured Entropy: " << std::setprecision(4) << res.measured_entropy << " bits/byte (Expected ~0.0). "
                << (res.is_verified ? "Passed." : "Failed.");

    } else if (method == sanitization::SanitizationMethod::DOD_5220_22_M ||
               method == sanitization::SanitizationMethod::PSEUDORANDOM_1_PASS) {
        // Expected random bytes: entropy should be > 7.5
        res.is_verified = (res.measured_entropy >= 7.2);
        res.match_rate_percentage = 100.0; // Statistical check

        details << "Pattern verification (Pseudorandom): Measured Entropy: "
                << std::fixed << std::setprecision(4) << res.measured_entropy << " bits/byte (Expected > 7.2). "
                << (res.is_verified ? "High entropy randomness verified." : "Entropy too low; possible incomplete overwrite.");
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
