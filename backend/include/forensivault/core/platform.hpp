#pragma once

#include <string>
#include <vector>
#include <filesystem>
#include <system_error>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <sstream>
#include <set>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winioctl.h>
#include <shlobj.h>
#include <shellapi.h>
#include <io.h>
#else
#include <unistd.h>
#include <climits>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#if defined(__linux__)
#include <sys/ioctl.h>
#include <linux/fs.h>
#endif
#endif

namespace forensivault::core {

class Platform {
public:
    /**
     * @brief Checks whether the current process is running with administrative / root elevation.
     *        On Linux: Checks if effective user ID is 0 (root).
     *        On Windows: Checks if the current security token has TokenElevation enabled.
     */
    static inline bool isElevated() noexcept {
#if defined(_WIN32)
        BOOL elevated = FALSE;
        HANDLE token = NULL;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
            TOKEN_ELEVATION elevation;
            DWORD size = sizeof(TOKEN_ELEVATION);
            if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
                elevated = elevation.TokenIsElevated;
            }
            CloseHandle(token);
        }
        return elevated != 0;
#elif defined(__linux__) || defined(__unix__) || defined(__APPLE__)
        return geteuid() == 0;
#else
        return false;
#endif
    }

    /**
     * @brief Returns human-readable platform-specific guidance on how to run with elevated privileges.
     */
    static inline std::string getElevationHelp() {
#if defined(_WIN32)
        return "Windows Administrator elevation required. Right-click your terminal (PowerShell/CMD) and select 'Run as administrator'.";
#elif defined(__linux__)
        return "Linux root (sudo) privileges required. Re-run this command with 'sudo': e.g., sudo ./forensivault_cli";
#else
        return "Administrative / superuser privileges required to perform this action.";
#endif
    }

    /**
     * @brief Dynamically resolves the user's home directory. Zero hardcoded paths.
     */
    static inline std::string getUserHomeDirectory() {
#if defined(_WIN32)
        const char* profile = std::getenv("USERPROFILE");
        if (profile && *profile) return profile;
        const char* drive = std::getenv("HOMEDRIVE");
        const char* path = std::getenv("HOMEPATH");
        if (drive && path) return std::string(drive) + path;
        return ".";
#else
        const char* home = std::getenv("HOME");
        if (home && *home) return home;
        return ".";
#endif
    }

    /**
     * @brief Dynamically resolves the absolute path of the currently running binary.
     *        Zero hardcoded paths.
     */
    static inline std::string getExecutablePath() {
#if defined(_WIN32)
        wchar_t buf[MAX_PATH];
        DWORD len = GetModuleFileNameW(NULL, buf, MAX_PATH);
        if (len > 0) {
            int size = WideCharToMultiByte(CP_UTF8, 0, buf, len, NULL, 0, NULL, NULL);
            std::string res(size, 0);
            WideCharToMultiByte(CP_UTF8, 0, buf, len, &res[0], size, NULL, NULL);
            return res;
        }
        return "";
#elif defined(__linux__)
        char buf[PATH_MAX];
        ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
        if (len != -1) {
            buf[len] = '\0';
            return std::string(buf);
        }
        return "";
#elif defined(__APPLE__)
        char buf[1024];
        uint32_t size = sizeof(buf);
        if (_NSGetExecutablePath(buf, &size) == 0) return std::string(buf);
        return "";
#else
        return "";
#endif
    }

    /**
     * @brief Elevates the current application to root / administrator on the fly.
     *        On Linux: prompts the user for their sudo password in the active terminal,
     *                  then replaces the process image via execvp.
     *        On Windows: invokes the UAC dialog via ShellExecuteExW(runas).
     */
    static inline bool elevateProcess(const std::vector<std::string>& extraArgs = {}) {
#if defined(__linux__) || defined(__unix__) || defined(__APPLE__)
        if (isElevated()) return true;
        std::string exe = getExecutablePath();
        if (exe.empty()) return false;

        // Prompt user for sudo password interactively in the terminal
        int auth = system("sudo -v");
        if (auth != 0) {
            return false;
        }

        std::vector<std::string> cmdArgs;
        cmdArgs.push_back("sudo");
        cmdArgs.push_back(exe);
        for (const auto& a : extraArgs) {
            cmdArgs.push_back(a);
        }

        std::vector<char*> cArgs;
        for (auto& s : cmdArgs) {
            cArgs.push_back(s.data());
        }
        cArgs.push_back(nullptr);

        execvp("sudo", cArgs.data());
        return false;
#elif defined(_WIN32)
        if (isElevated()) return true;
        std::string exe = getExecutablePath();
        if (exe.empty()) return false;

        std::string params;
        for (const auto& arg : extraArgs) {
            if (!params.empty()) params += " ";
            if (arg.find(' ') != std::string::npos && arg.front() != '\"') {
                params += "\"" + arg + "\"";
            } else {
                params += arg;
            }
        }

        int size_needed = MultiByteToWideChar(CP_UTF8, 0, exe.c_str(), -1, NULL, 0);
        std::wstring wExe(size_needed, 0);
        MultiByteToWideChar(CP_UTF8, 0, exe.c_str(), -1, &wExe[0], size_needed);

        std::wstring wParams;
        if (!params.empty()) {
            int psize = MultiByteToWideChar(CP_UTF8, 0, params.c_str(), -1, NULL, 0);
            wParams.resize(psize);
            MultiByteToWideChar(CP_UTF8, 0, params.c_str(), -1, &wParams[0], psize);
        }

        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        sei.hwnd = GetForegroundWindow();
        sei.lpVerb = L"runas";
        sei.lpFile = wExe.c_str();
        sei.lpParameters = wParams.empty() ? NULL : wParams.c_str();
        sei.lpDirectory = NULL;
        sei.nShow = SW_SHOWNORMAL;

        if (ShellExecuteExW(&sei)) {
            if (sei.hProcess != NULL) {
                WaitForSingleObject(sei.hProcess, INFINITE);
                CloseHandle(sei.hProcess);
            }
            return true;
        }
        return false;
#else
        return false;
#endif
    }

    /**
     * @brief Synchronizes file contents and metadata to persistent physical storage,
     *        bypassing and flushing OS page cache and hardware drive write cache.
     */
    static inline bool flushFileBuffers(int fd) noexcept {
#if defined(_WIN32)
        intptr_t osfhandle = _get_osfhandle(fd);
        if (osfhandle == -1) return false;
        return FlushFileBuffers(reinterpret_cast<HANDLE>(osfhandle)) != 0;
#elif defined(__linux__)
        // fdatasync flushes data and required metadata, fsync flushes all metadata
        return (fdatasync(fd) == 0 || fsync(fd) == 0);
#elif defined(__unix__) || defined(__APPLE__)
        return fsync(fd) == 0;
#else
        return false;
#endif
    }

    /**
     * @brief Synchronizes Windows HANDLE directly to physical storage.
     */
#if defined(_WIN32)
    static inline bool flushHandle(HANDLE hFile) noexcept {
        return FlushFileBuffers(hFile) != 0;
    }
#endif

    /**
     * @brief Checks whether the specified path or device refers to the internal main storage drive
     *        (the active physical drive or partition hosting the OS root / system installation).
     *        Destructive drive sanitization and deletion MUST be permanently blocked for this drive,
     *        even with root / administrator privileges.
     */
    static inline bool isMainSystemDrive(const std::filesystem::path& targetPath) {
        std::string s = targetPath.lexically_normal().string();
        if (s.empty()) return false;

#if defined(__linux__)
        std::string devName = targetPath.filename().string();

        std::ifstream ifs("/proc/mounts");
        if (!ifs) return false;

        std::set<std::string> rootBaseDisks;
        std::set<std::string> rootPartitions;

        std::string line;
        while (std::getline(ifs, line)) {
            std::istringstream iss(line);
            std::string mDev, mPoint;
            if (iss >> mDev >> mPoint) {
                if (mPoint == "/" || mPoint == "/boot" || mPoint == "/boot/efi" || mPoint == "/etc") {
                    rootPartitions.insert(mDev);
                    std::string partName = std::filesystem::path(mDev).filename().string();
                    rootPartitions.insert(partName);

                    // Find parent disk in sysfs: /sys/class/block/<partName>
                    std::error_code ec;
                    std::filesystem::path sysPath = "/sys/class/block/" + partName;
                    if (std::filesystem::is_symlink(sysPath, ec)) {
                        auto target = std::filesystem::read_symlink(sysPath, ec);
                        if (!ec) {
                            auto parentDir = target.parent_path().filename().string();
                            if (!parentDir.empty()) {
                                rootBaseDisks.insert(parentDir);
                                rootBaseDisks.insert("/dev/" + parentDir);
                            }
                        }
                    }

                    // Fallback heuristics: nvme0n1p2 -> nvme0n1, sda2 -> sda
                    if (partName.rfind("nvme", 0) == 0 || partName.rfind("mmcblk", 0) == 0) {
                        size_t pPos = partName.rfind('p');
                        if (pPos != std::string::npos && pPos > 0) {
                            std::string base = partName.substr(0, pPos);
                            rootBaseDisks.insert(base);
                            rootBaseDisks.insert("/dev/" + base);
                        }
                    } else if (partName.rfind("sd", 0) == 0 || partName.rfind("vd", 0) == 0 || partName.rfind("hd", 0) == 0) {
                        size_t numPos = partName.find_first_of("0123456789");
                        if (numPos != std::string::npos && numPos > 0) {
                            std::string base = partName.substr(0, numPos);
                            rootBaseDisks.insert(base);
                            rootBaseDisks.insert("/dev/" + base);
                        }
                    }
                }
            }
        }

        if (rootPartitions.count(s) || rootPartitions.count(devName)) {
            return true;
        }
        if (rootBaseDisks.count(s) || rootBaseDisks.count(devName)) {
            return true;
        }

        for (const auto& base : rootBaseDisks) {
            if (s == base || devName == base) return true;
            if (s.rfind(base + "p", 0) == 0 || s.rfind(base, 0) == 0) return true;
            if (s.rfind("/dev/" + base + "p", 0) == 0 || s.rfind("/dev/" + base, 0) == 0) return true;
        }

        return false;
#elif defined(_WIN32)
        std::replace(s.begin(), s.end(), '/', '\\');
        std::string lower = s;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

        char sysDriveLetter = 'c';
        wchar_t winDir[MAX_PATH];
        if (GetWindowsDirectoryW(winDir, MAX_PATH) > 0 && winDir[1] == L':') {
            sysDriveLetter = static_cast<char>(std::tolower(winDir[0]));
        }

        std::string letterStr(1, sysDriveLetter);
        if (lower == letterStr + ":" || lower == letterStr + ":\\" ||
            lower == "\\\\.\\" + letterStr + ":") {
            return true;
        }

        std::string sysDriveDevice = "\\\\.\\" + letterStr + ":";
        HANDLE hVol = CreateFileA(sysDriveDevice.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  NULL, OPEN_EXISTING, 0, NULL);
        if (hVol != INVALID_HANDLE_VALUE) {
            STORAGE_DEVICE_NUMBER sdn;
            DWORD bytesRet = 0;
            if (DeviceIoControl(hVol, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0,
                                &sdn, sizeof(sdn), &bytesRet, NULL)) {
                CloseHandle(hVol);
                std::string physDrive = "\\\\.\\physicaldrive" + std::to_string(sdn.DeviceNumber);
                if (lower == physDrive) {
                    return true;
                }
            } else {
                CloseHandle(hVol);
            }
        }

        if (lower == "\\\\.\\physicaldrive0" && sysDriveLetter == 'c') {
            return true;
        }

        return false;
#else
        return false;
#endif
    }

    /**
     * @brief Strictly checks whether a given path is the OS root drive, internal main drive,
     *        or a critical OS system path (/root, C:\, /boot, etc.).
     *        Destructive operations (erase, sanitize) MUST NEVER touch these paths,
     *        even when running with root (sudo) or administrator privileges.
     */
    static inline bool isRootOrSystemPath(const std::filesystem::path& targetPath) {
        namespace fs = std::filesystem;
        std::error_code ec;

        fs::path p = targetPath;
        if (fs::exists(p, ec)) {
            p = fs::canonical(p, ec);
            if (ec) {
                p = fs::absolute(targetPath, ec);
            }
        } else {
            p = fs::absolute(targetPath, ec);
        }

        std::string s = p.lexically_normal().string();

        // 1. Strictly block the internal main storage drive or partition
        if (isMainSystemDrive(targetPath) || isMainSystemDrive(p)) {
            return true;
        }

#if defined(_WIN32)
        std::replace(s.begin(), s.end(), '/', '\\');
        std::string lower = s;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

        char sysDriveLetter = 'c';
        wchar_t winDir[MAX_PATH];
        if (GetWindowsDirectoryW(winDir, MAX_PATH) > 0 && winDir[1] == L':') {
            sysDriveLetter = static_cast<char>(std::tolower(winDir[0]));
        }
        std::string sysDriveRoot = std::string(1, sysDriveLetter) + ":";

        // C:\ or C:
        if (lower == sysDriveRoot || lower == sysDriveRoot + "\\") {
            return true;
        }

        // Critical system directories on the main Windows system drive
        static const std::vector<std::string> winProtected = {
            "\\windows",
            "\\program files",
            "\\program files (x86)",
            "\\programdata",
            "\\system volume information",
            "\\$recycle.bin",
            "\\recovery",
            "\\boot",
            "\\users"
        };

        for (const auto& prefix : winProtected) {
            std::string fullPrefix = sysDriveRoot + prefix;
            if (lower == fullPrefix || lower.rfind(fullPrefix + "\\", 0) == 0) {
                return true;
            }
        }
#else
        // POSIX / Linux root check: "/" or empty
        if (s == "/" || s.empty()) {
            return true;
        }

        // Critical Linux system hierarchy paths on the root filesystem:
        // /root (root user directory), /boot, /etc, /bin, /sbin, /usr, /lib*, /var, /proc, /sys, /run
        static const std::vector<std::string> linuxProtected = {
            "/root",
            "/bin",
            "/boot",
            "/etc",
            "/lib",
            "/lib32",
            "/lib64",
            "/libx32",
            "/proc",
            "/run",
            "/sbin",
            "/sys",
            "/usr",
            "/var"
        };

        for (const auto& prefix : linuxProtected) {
            if (s == prefix || s.rfind(prefix + "/", 0) == 0) {
                return true;
            }
        }

        // Protect /dev system mount directories while allowing external block devices (/dev/sdb, etc.)
        if (s == "/dev" || s == "/dev/" ||
            s.rfind("/dev/pts", 0) == 0 || s.rfind("/dev/shm", 0) == 0 ||
            s.rfind("/dev/mqueue", 0) == 0 || s.rfind("/dev/hugepages", 0) == 0) {
            return true;
        }
#endif
        return false;
    }
};

} // namespace forensivault::core
