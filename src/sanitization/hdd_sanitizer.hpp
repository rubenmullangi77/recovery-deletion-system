#pragma once

#include "sanitization/drive_types.hpp"
#include "sanitization/sanitization_strategy.hpp"
#include <string>
#include <vector>
#include <memory>

namespace forensivault {
namespace sanitization {

class HDDSanitizer {
public:
    HDDSanitizer() = default;

    /**
     * @brief Evaluates whether a strategy is suitable for rotational magnetic hard drives.
     */
    static bool isStrategySupported(const SanitizationStrategy& strategy);

    /**
     * @brief Returns recommended strategy for rotational hard drives.
     */
    static std::unique_ptr<SanitizationStrategy> getRecommendedStrategy();

    /**
     * @brief Explains magnetic media forensic factors and limitations.
     */
    static std::vector<std::string> getForensicConsiderations();
};

} // namespace sanitization
} // namespace forensivault
