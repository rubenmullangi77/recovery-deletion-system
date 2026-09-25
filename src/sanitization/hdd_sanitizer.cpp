#include "sanitization/hdd_sanitizer.hpp"

namespace forensivault {
namespace sanitization {

bool HDDSanitizer::isStrategySupported(const SanitizationStrategy& strategy) {
    return strategy.isApplicableTo(DriveMediaType::HDD_ROTATIONAL);
}

std::unique_ptr<SanitizationStrategy> HDDSanitizer::getRecommendedStrategy() {
    return std::make_unique<Dod522022MStrategy>();
}

std::vector<std::string> HDDSanitizer::getForensicConsiderations() {
    return {
        "Magnetic Rotational Storage: Multi-pass overwriting (0x00, 0xFF, Random) successfully eliminates residual magnetic domains on modern high-density tracks.",
        "G-List (Grown Defect List): Sectors retired by drive firmware cannot be addressed by host LBA writes and retain previous data.",
        "DCO (Device Configuration Overlay) & HPA (Host Protected Area): Hidden partitions must be unlocked via ATA commands to ensure comprehensive sanitization.",
        "NIST SP 800-88 Rev 1 concludes that a single overwrite pass (Clear) is cryptographically and forensically sufficient for drives manufactured after 2001."
    };
}

} // namespace sanitization
} // namespace forensivault
