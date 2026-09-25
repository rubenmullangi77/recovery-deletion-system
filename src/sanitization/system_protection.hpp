#pragma once

#include <string>
#include <vector>

namespace forensivault {
namespace sanitization {

class SystemProtectionGuard {
public:
    SystemProtectionGuard() = default;

    /**
     * @brief Evaluates whether a target path is a prohibited system directory or file.
     * @param targetPath Path to inspect.
     * @param outReason If prohibited, receives the explanation of why it is protected.
     * @return True if the path is protected (ERASURE PROHIBITED), false if safe to process.
     */
    static bool isProtected(const std::string& targetPath, std::string& outReason);

    /**
     * @brief Checks if a path represents a drive root (e.g. "C:\", "D:", "/").
     */
    static bool isDriveRoot(const std::string& targetPath);

    /**
     * @brief Validates a list of items; returns true if all items pass safety checks.
     */
    static bool validateAll(const std::vector<std::string>& paths, std::vector<std::string>& violations);

private:
    static std::string normalizePath(const std::string& rawPath);
};

} // namespace sanitization
} // namespace forensivault
