#include "sanitization/system_protection.hpp"
#include "forensivault/core/platform.hpp"
#include <filesystem>
#include <algorithm>
#include <cctype>

namespace fs = std::filesystem;

namespace forensivault {
namespace sanitization {

namespace {

std::string toUpper(std::string str) {
    std::transform(str.begin(), str.end(), str.begin(), [](unsigned char c) {
        return static_cast<char>(std::toupper(c));
    });
    return str;
}

std::string canonicalizeSafe(const std::string& raw) {
    try {
        if (raw.length() >= 2 &&
            std::isalpha(static_cast<unsigned char>(raw[0])) &&
            raw[1] == ':') {
            if (raw.length() == 2) {
                return std::string(1, raw[0]) + ":\\";
            }
#ifndef _WIN32
            // On non-Windows platforms, preserve Windows drive paths as absolute Windows paths
            std::string winPath = raw;
            std::replace(winPath.begin(), winPath.end(), '/', '\\');
            return winPath;
#endif
        }

        fs::path p(raw);

        if (fs::exists(p)) {
            return fs::weakly_canonical(p).string();
        }

        return fs::absolute(p).lexically_normal().string();
    }
    catch (...) {
        return raw;
    }
}

} // anonymous namespace

std::string SystemProtectionGuard::normalizePath(const std::string& rawPath) {
    std::string s = canonicalizeSafe(rawPath);
    // Replace all forward slashes with backslashes for unified comparison
    std::replace(s.begin(), s.end(), '/', '\\');
    // Remove trailing backslash if not root (e.g. "C:\" -> keep "C:\", but "C:\foo\" -> "C:\foo")
    if (s.length() > 3 && s.back() == '\\') {
        s.pop_back();
    }
    return toUpper(s);
}

bool SystemProtectionGuard::isDriveRoot(const std::string& targetPath) {
    std::string norm = normalizePath(targetPath);
    if (norm == "\\" || norm == "/" || norm.empty()) {
        return true;
    }
    // Check Windows drive root: e.g. "C:", "C:\", "D:", "D:\"
    if (norm.length() == 2 && std::isalpha(static_cast<unsigned char>(norm[0])) && norm[1] == ':') {
        return true;
    }
    if (norm.length() == 3 && std::isalpha(static_cast<unsigned char>(norm[0])) && norm[1] == ':' && norm[2] == '\\') {
        return true;
    }
    return false;
}

bool SystemProtectionGuard::isProtected(const std::string& targetPath, std::string& outReason) {
    if (targetPath.empty()) {
        outReason = "Path is empty.";
        return true;
    }

    if (core::Platform::isMainSystemDrive(targetPath)) {
        outReason = "Target is the active OS internal main storage drive (" + targetPath + "). Erasure is permanently prohibited even with root/admin privileges.";
        return true;
    }

    if (core::Platform::isRootOrSystemPath(targetPath)) {
        outReason = "Target is OS root directory, /root, or critical system path (" + targetPath + "). Erasure is permanently prohibited even with root/admin privileges.";
        return true;
    }

    if (isDriveRoot(targetPath)) {
        outReason = "Target is a drive root directory. Drive-level root deletion is strictly prohibited.";
        return true;
    }

    std::string norm = normalizePath(targetPath);

    // List of prohibited system path prefixes (Windows and Linux)
    const std::vector<std::string> systemPrefixes = {
        "\\WINDOWS",
        "\\PROGRAM FILES",
        "\\PROGRAM FILES (X86)",
        "\\PROGRAMDATA",
        "\\SYSTEM VOLUME INFORMATION",
        "\\$RECYCLE.BIN",
        "\\RECOVERY",
        "\\BOOT",
        // Linux system directories
        "\\BIN",
        "\\SBIN",
        "\\ETC",
        "\\LIB",
        "\\LIB64",
        "\\PROC",
        "\\SYS",
        "\\DEV",
        "\\ROOT",
        "\\RUN",
        "\\USR",
        "\\VAR"
    };

    // Check against drive-qualified prefixes (e.g. "C:\WINDOWS") or root prefixes (e.g. "\etc")
    for (const auto& prefix : systemPrefixes) {
        // Drive relative: "C:\WINDOWS" or root-relative: "\WINDOWS"
        if (norm.length() >= 2 && norm[1] == ':') {
            std::string sub = norm.substr(2); // Skip "C:"
            if (sub == prefix || sub.rfind(prefix + "\\", 0) == 0) {
                outReason = "Target is an essential Operating System directory (" + prefix.substr(1) + "). Erasure is strictly blocked.";
                return true;
            }
        } else if (norm == prefix || norm.rfind(prefix + "\\", 0) == 0) {
            outReason = "Target is an essential Operating System directory (" + prefix.substr(1) + "). Erasure is strictly blocked.";
            return true;
        }
    }

    // Prohibited system files
    const std::vector<std::string> prohibitedFiles = {
        "PAGEFILE.SYS",
        "HIBERFIL.SYS",
        "SWAPFILE.SYS",
        "BOOTMGR",
        "BOOTNXT",
        "NTLDR",
        "NTDETECT.COM",
        "VMLINUZ",
        "INITRD.IMG"
    };

    std::string filename = norm;
    size_t lastSlash = norm.find_last_of("\\/");
    if (lastSlash != std::string::npos) {
        filename = norm.substr(lastSlash + 1);
    }

    for (const auto& file : prohibitedFiles) {
        if (filename == file) {
            outReason = "Target is a critical system paging or boot file (" + file + "). Erasure is strictly blocked.";
            return true;
        }
    }

    // Allow safe test delete folders
    if (norm.find("\\FORENSIVAULT_TEST_DELETE") != std::string::npos ||
        norm.find("\\TEST_DATA\\DISPOSABLE") != std::string::npos) {
        return false;
    }

    // Protect user AppData
    if (norm.find("\\APPDATA") != std::string::npos) {
        outReason = "Target is within the user AppData directory. Configuration erasure is strictly blocked.";
        return true;
    }

    // Protect "C:\Users" or Linux "/home" root directory itself (though subfolders of users can be processed)
    if (norm.length() >= 2 && norm[1] == ':') {
        std::string sub = norm.substr(2);
        if (sub == "\\USERS" || sub == "\\USERS\\DEFAULT" || sub == "\\USERS\\PUBLIC" || sub == "\\USERS\\ALL USERS") {
            outReason = "Target is a root user profile directory (" + sub.substr(1) + "). Erasure is blocked to prevent profile corruption.";
            return true;
        }
    } else if (norm == "\\HOME" || norm == "\\ROOT") {
        outReason = "Target is a root user profile directory (" + norm.substr(1) + "). Erasure is blocked to prevent profile corruption.";
        return true;
    }

    // Protect application codebase directory unless inside allowed test folder
    try {
        std::string cwdNorm = normalizePath(fs::current_path().string());
        if (!cwdNorm.empty() && (norm == cwdNorm || norm.rfind(cwdNorm + "\\", 0) == 0)) {
            outReason = "Target is within the ForensiVault application directory. Codebase erasure is strictly blocked.";
            return true;
        }
    } catch (...) {}
    if (norm == "D:\\SIH" || norm.rfind("D:\\SIH\\", 0) == 0) {
        outReason = "Target is within the ForensiVault application directory. Codebase erasure is strictly blocked.";
        return true;
    }

    return false;
}

bool SystemProtectionGuard::validateAll(const std::vector<std::string>& paths, std::vector<std::string>& violations) {
    violations.clear();
    for (const auto& p : paths) {
        std::string reason;
        if (isProtected(p, reason)) {
            violations.push_back(p + ": " + reason);
        }
    }
    return violations.empty();
}

} // namespace sanitization
} // namespace forensivault
