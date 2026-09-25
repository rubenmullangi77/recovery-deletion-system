#pragma once

#include "sanitization/drive_types.hpp"
#include "sanitization/sanitization_strategy.hpp"
#include <string>
#include <vector>
#include <memory>

namespace forensivault {
namespace sanitization {

struct SsdSanitizationCapabilityReport {
    std::string device_identifier;
    bool supports_nvme_crypto_erase{false};
    bool supports_nvme_block_erase{false};
    bool supports_ata_enhanced_erase{false};
    bool supports_trim_deallocate{false};
    bool software_overwrite_sufficient{false}; // Always FALSE on physical SSDs!
    std::string recommended_method;
    std::vector<std::string> critical_disclosures;
    std::vector<std::string> unverifiable_aspects;
};

class SSDSanitizer {
public:
    SSDSanitizer() = default;

    /**
     * @brief Generates comprehensive SSD capability report and physical NAND disclosures.
     * @param props Target drive properties.
     * @return SsdSanitizationCapabilityReport.
     */
    static SsdSanitizationCapabilityReport evaluateCapabilities(const DriveProperties& props);

    /**
     * @brief Explains SSD NAND flash forensic realities.
     */
    static std::vector<std::string> getForensicConsiderations();

    /**
     * @brief Recommends standard-compliant sanitization strategy for SSDs.
     */
    static std::unique_ptr<SanitizationStrategy> getRecommendedStrategy();
};

} // namespace sanitization
} // namespace forensivault
