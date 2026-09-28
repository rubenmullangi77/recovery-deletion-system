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
#include <chrono>
#include <thread>

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
#include <sys/wait.h>
#include <fcntl.h>
#include <pwd.h>
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
        return (geteuid() == 0);
#else
        return false;
#endif
    }

    /**
     * @brief Cryptographically secure random number generator backed by OS kernel CSPRNG.
     *        Uses /dev/urandom with O_CLOEXEC on POSIX, BCryptGenRandom on Windows.
     */
    static inline bool getRandomBytes(uint8_t* buffer, size_t length) noexcept {
        if (!buffer || length == 0) return true;
#if defined(_WIN32)
        return BCryptGenRandom(NULL, buffer, static_cast<ULONG>(length), BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
#elif defined(__linux__) || defined(__unix__) || defined(__APPLE__)
        int fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (fd < 0) return false;
        size_t total = 0;
        while (total < length) {
            ssize_t n = ::read(fd, buffer + total, length - total);
            if (n > 0) total += static_cast<size_t>(n);
            else if (n < 0 && errno == EINTR) continue;
            else { ::close(fd); return false; }
        }
        ::close(fd);
        return true;
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
     *        When running under elevated root/administrator privileges (sudo, pkexec, doas, UAC),
     *        intelligently resolves the original calling user's home directory (e.g. /home/username)
     *        instead of /root or C:\Windows\system32.
     */
    static inline std::string getUserHomeDirectory() {
#if defined(_WIN32)
        // 1. Standard user profile
        const char* profile = std::getenv("USERPROFILE");
        if (profile && *profile) return profile;
        const char* drive = std::getenv("HOMEDRIVE");
        const char* path = std::getenv("HOMEPATH");
        if (drive && path) return std::string(drive) + path;
        return ".";
#else
        // 1. If running under sudo, respect the original caller's SUDO_USER
        const char* sudoUser = std::getenv("SUDO_USER");
        if (sudoUser && *sudoUser && std::string(sudoUser) != "root") {
            struct passwd* pw = getpwnam(sudoUser);
            if (pw && pw->pw_dir && *(pw->pw_dir)) {
                return std::string(pw->pw_dir);
            }
        }

        // 2. If running under pkexec / polkit
        const char* pkexecUid = std::getenv("PKEXEC_UID");
        if (pkexecUid && *pkexecUid) {
            uid_t uid = static_cast<uid_t>(std::atoi(pkexecUid));
            if (uid > 0) {
                struct passwd* pw = getpwuid(uid);
                if (pw && pw->pw_dir && *(pw->pw_dir)) {
                    return std::string(pw->pw_dir);
                }
            }
        }

        // 3. If running under doas
        const char* doasUser = std::getenv("DOAS_USER");
        if (doasUser && *doasUser && std::string(doasUser) != "root") {
            struct passwd* pw = getpwnam(doasUser);
            if (pw && pw->pw_dir && *(pw->pw_dir)) {
                return std::string(pw->pw_dir);
            }
        }

        // 4. Check Linux audit loginuid if running as root
        if (geteuid() == 0) {
            std::ifstream loginuidFile("/proc/self/loginuid");
            if (loginuidFile.is_open()) {
                unsigned long loginuid = 0;
                if (loginuidFile >> loginuid && loginuid > 0 && loginuid < 4294967295UL) {
                    struct passwd* pw = getpwuid(static_cast<uid_t>(loginuid));
                    if (pw && pw->pw_dir && *(pw->pw_dir) && std::string(pw->pw_dir) != "/root") {
                        return std::string(pw->pw_dir);
                    }
                }
            }

            // Fallback: check getlogin()
            const char* loginName = getlogin();
            if (loginName && *loginName && std::string(loginName) != "root") {
                struct passwd* pw = getpwnam(loginName);
                if (pw && pw->pw_dir && *(pw->pw_dir)) {
                    return std::string(pw->pw_dir);
                }
            }
        }

        // 5. Standard non-root HOME environment variable
        const char* home = std::getenv("HOME");
        if (home && *home && (geteuid() != 0 || std::string(home) != "/root")) {
            return std::string(home);
        }

        // 6. If root and /home contains user directories, select first user home directory
        if (geteuid() == 0) {
            try {
                if (std::filesystem::exists("/home")) {
                    for (const auto& entry : std::filesystem::directory_iterator("/home")) {
                        if (entry.is_directory()) {
                            std::string candidate = entry.path().string();
                            if (candidate != "/home/lost+found") {
                                return candidate;
                            }
                        }
                    }
                }
            } catch (...) {}
        }

        if (home && *home) return std::string(home);
        return ".";
#endif
    }

    /**
     * @brief Resolves the user-level configuration directory for ForensiVault.
     *        Linux/POSIX: $XDG_CONFIG_HOME/forensicvault or ~/.config/forensicvault
     *        Windows: %APPDATA%\forensicvault
     */
    static inline std::string getConfigDirectory() {
#if defined(_WIN32)
        const char* appData = std::getenv("APPDATA");
        if (appData && *appData) {
            return std::string(appData) + "\\forensicvault";
        }
        return getUserHomeDirectory() + "\\AppData\\Roaming\\forensicvault";
#else
        const char* xdgConfig = std::getenv("XDG_CONFIG_HOME");
        if (xdgConfig && *xdgConfig) {
            return std::string(xdgConfig) + "/forensicvault";
        }
        return getUserHomeDirectory() + "/.config/forensicvault";
#endif
    }

    /**
     * @brief Resolves the forensic reports directory.
     *        Linux/POSIX: ~/.config/forensicvault/reports
     *        Windows: %APPDATA%\forensicvault\reports
     */
    static inline std::string getReportsDirectory() {
#if defined(_WIN32)
        return getConfigDirectory() + "\\reports";
#else
        return getConfigDirectory() + "/reports";
#endif
    }

    /**
     * @brief Ensures config and report directories exist with secure permissions.
     *        Automatically migrates legacy misspelled forensivault directory if present.
     */
    static inline void ensureConfigDirectories() {
        std::string cfg = getConfigDirectory();
        std::string rep = getReportsDirectory();
        std::error_code ec;

#if !defined(_WIN32)
        // Automatic migration from misspelled legacy .config/forensivault
        std::string legacyCfg = getUserHomeDirectory() + "/.config/forensivault";
        if (std::filesystem::exists(legacyCfg, ec) && !std::filesystem::exists(cfg, ec)) {
            std::filesystem::create_directories(cfg, ec);
            ::chmod(cfg.c_str(), 0700);
            for (const auto& item : std::filesystem::directory_iterator(legacyCfg, ec)) {
                std::filesystem::copy(item.path(), std::filesystem::path(cfg) / item.path().filename(),
                                      std::filesystem::copy_options::skip_existing, ec);
            }
        }
#endif

        std::filesystem::create_directories(cfg, ec);
#if !defined(_WIN32)
        ::chmod(cfg.c_str(), 0700);
#endif

        std::filesystem::create_directories(rep, ec);
#if !defined(_WIN32)
        ::chmod(rep.c_str(), 0700);
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
     *        On Linux: In desktop sessions, invokes the native graphical Polkit agent
     *                  (pkexec) forwarding display variables, or falls back to interactive
     *                  terminal sudo if running headless.
     *        On Windows: Invokes the native UAC elevation dialog via ShellExecuteExW(runas).
     */
    /**
     * @brief Trust Boundary Policy for Privileged Operations:
     *        ForensiVault core operates as an unprivileged process. Sanitization and recovery
     *        operate strictly on user files and forensic disk images without elevated privileges.
     *        Full-process monolithic elevation (running GUI / parser attack surface under EUID 0 / UAC)
     *        is permanently prohibited to maintain forensic soundness and prevent privilege escalation.
     *        Physical block device operations requiring kernel privileges must be delegated to a
     *        dedicated helper with a strictly constrained IPC boundary, rather than elevating the GUI.
     */
    static inline bool elevateProcess(const std::vector<std::string>& /*extraArgs*/ = {}) {
        // Monolithic full-process elevation is disabled by security policy.
        // ForensicVault strictly operates with unprivileged least-privilege credentials.
        return false;
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

#if defined(__linux__)
    /**
     * @brief Recursively resolves underlying block device topology for Linux storage devices.
     *        Traverses /sys/class/block/<dev>/slaves and partition parent links to find all
     *        base physical storage disks and intermediate device-mapper / partition layers.
     */
    static inline void resolveBlockDeviceSlaves(
        const std::string& devName,
        std::set<std::string>& outDisks,
        const std::string& sysfsBlockDir = "/sys/class/block",
        std::set<std::string>* visited = nullptr) {

        std::set<std::string> localVisited;
        if (!visited) {
            visited = &localVisited;
        }

        namespace fs = std::filesystem;
        std::error_code ec;

        if (devName.empty()) return;

        std::string name = devName;
        // Strip /dev/mapper/ or /dev/ prefix if present
        if (name.rfind("/dev/mapper/", 0) == 0) {
            name = name.substr(12);
        } else if (name.rfind("/dev/", 0) == 0) {
            name = name.substr(5);
        }

        if (name.empty()) return;

        // Visited guard: ensure device name is only traversed once to prevent infinite loops on cyclic topologies
        if (!visited->insert(name).second) {
            return;
        }

        // Canonicalize if this is an actual filesystem node pointing to a device node (e.g. /dev/mapper/vg-root -> /dev/dm-0)
        fs::path p("/dev/" + name);
        if (fs::exists(p, ec) && fs::is_symlink(p, ec)) {
            fs::path canon = fs::canonical(p, ec);
            if (!ec) {
                std::string cName = canon.filename().string();
                if (!cName.empty() && cName != name) {
                    outDisks.insert(cName);
                    outDisks.insert("/dev/" + cName);
                    if (visited->find(cName) == visited->end()) {
                        resolveBlockDeviceSlaves(cName, outDisks, sysfsBlockDir, visited);
                    }
                }
            }
        }

        outDisks.insert(name);
        outDisks.insert("/dev/" + name);

        fs::path sysPath = fs::path(sysfsBlockDir) / name;
        if (!fs::exists(sysPath, ec)) {
            // Check fallback heuristics for partitions
            if (name.rfind("nvme", 0) == 0 || name.rfind("mmcblk", 0) == 0) {
                size_t pPos = name.rfind('p');
                if (pPos != std::string::npos && pPos > 0) {
                    std::string base = name.substr(0, pPos);
                    outDisks.insert(base);
                    outDisks.insert("/dev/" + base);
                    if (visited->find(base) == visited->end()) {
                        resolveBlockDeviceSlaves(base, outDisks, sysfsBlockDir, visited);
                    }
                }
            } else if (name.rfind("sd", 0) == 0 || name.rfind("vd", 0) == 0 ||
                       name.rfind("hd", 0) == 0 || name.rfind("xvd", 0) == 0) {
                size_t numPos = name.find_first_of("0123456789");
                if (numPos != std::string::npos && numPos > 0) {
                    std::string base = name.substr(0, numPos);
                    outDisks.insert(base);
                    outDisks.insert("/dev/" + base);
                    if (visited->find(base) == visited->end()) {
                        resolveBlockDeviceSlaves(base, outDisks, sysfsBlockDir, visited);
                    }
                }
            }
            return;
        }

        // 1. Recurse into 'slaves' directory (LVM, dm-crypt / LUKS, mdraid)
        fs::path slavesDir = sysPath / "slaves";
        if (fs::exists(slavesDir, ec) && fs::is_directory(slavesDir, ec)) {
            for (const auto& entry : fs::directory_iterator(slavesDir, ec)) {
                std::string slaveName = entry.path().filename().string();
                if (!slaveName.empty() && slaveName != "." && slaveName != "..") {
                    outDisks.insert(slaveName);
                    outDisks.insert("/dev/" + slaveName);
                    if (visited->find(slaveName) == visited->end()) {
                        resolveBlockDeviceSlaves(slaveName, outDisks, sysfsBlockDir, visited);
                    }
                }
            }
        }

        // 2. Resolve parent disk for partition nodes via sysfs symlink
        if (fs::is_symlink(sysPath, ec)) {
            fs::path target = fs::read_symlink(sysPath, ec);
            if (!ec) {
                std::string parentName = target.parent_path().filename().string();
                if (!parentName.empty() && parentName != "block" && parentName != "." && parentName != name) {
                    outDisks.insert(parentName);
                    outDisks.insert("/dev/" + parentName);
                    if (visited->find(parentName) == visited->end()) {
                        resolveBlockDeviceSlaves(parentName, outDisks, sysfsBlockDir, visited);
                    }
                }
            }
        }

        // 3. Fallback partition heuristic
        if (fs::exists(sysPath / "partition", ec)) {
            if (name.rfind("nvme", 0) == 0 || name.rfind("mmcblk", 0) == 0) {
                size_t pPos = name.rfind('p');
                if (pPos != std::string::npos && pPos > 0) {
                    std::string base = name.substr(0, pPos);
                    outDisks.insert(base);
                    outDisks.insert("/dev/" + base);
                    if (visited->find(base) == visited->end()) {
                        resolveBlockDeviceSlaves(base, outDisks, sysfsBlockDir, visited);
                    }
                }
            } else if (name.rfind("sd", 0) == 0 || name.rfind("vd", 0) == 0 ||
                       name.rfind("hd", 0) == 0 || name.rfind("xvd", 0) == 0) {
                size_t numPos = name.find_first_of("0123456789");
                if (numPos != std::string::npos && numPos > 0) {
                    std::string base = name.substr(0, numPos);
                    outDisks.insert(base);
                    outDisks.insert("/dev/" + base);
                    if (visited->find(base) == visited->end()) {
                        resolveBlockDeviceSlaves(base, outDisks, sysfsBlockDir, visited);
                    }
                }
            }
        }
    }
#endif

    /**
     * @brief Checks whether the specified path or device refers to the internal main storage drive
     *        (the active physical drive or partition hosting the OS root / system installation).
     *        Destructive drive sanitization and deletion MUST be permanently blocked for this drive,
     *        even with root / administrator privileges.
     *        Fails closed (returns true) if system drive status cannot be reliably verified.
     */
    static inline bool isMainSystemDrive(
        const std::filesystem::path& targetPath,
        const std::string& mountsFilePath = "/proc/mounts",
        const std::string& sysfsBlockDir = "/sys/class/block") {

        std::string s = targetPath.lexically_normal().string();
        if (s.empty()) return true; // Fail-closed on empty target

#if defined(__linux__)
        std::string devName = targetPath.filename().string();
        std::error_code ec;

        std::string canonDevName = devName;
        if (targetPath.is_absolute() && std::filesystem::exists(targetPath, ec)) {
            auto canon = std::filesystem::canonical(targetPath, ec);
            if (!ec) {
                canonDevName = canon.filename().string();
            }
        }

        std::ifstream ifs(mountsFilePath);
        if (!ifs) {
            // FAIL-CLOSED: Cannot read mounts file, protect target by default
            return true;
        }

        std::set<std::string> rootProtectedDisks;
        std::string line;
        bool foundRootMount = false;

        while (std::getline(ifs, line)) {
            std::istringstream iss(line);
            std::string mDev, mPoint;
            if (iss >> mDev >> mPoint) {
                if (mPoint == "/" || mPoint == "/boot" || mPoint == "/boot/efi" || mPoint == "/etc" || mPoint == "/usr") {
                    foundRootMount = true;
                    rootProtectedDisks.insert(mDev);
                    std::string pName = std::filesystem::path(mDev).filename().string();
                    rootProtectedDisks.insert(pName);

                    // Recursively resolve LVM, LUKS, partitions, and base physical disks
                    resolveBlockDeviceSlaves(mDev, rootProtectedDisks, sysfsBlockDir);
                }
            }
        }

        // FAIL-CLOSED: If no root mount point could be resolved, fail closed
        if (!foundRootMount) {
            return true;
        }

        if (rootProtectedDisks.count(s) || rootProtectedDisks.count(devName) || rootProtectedDisks.count(canonDevName)) {
            return true;
        }

        for (const auto& base : rootProtectedDisks) {
            if (s == base || devName == base || canonDevName == base) return true;
            if (s.rfind(base + "p", 0) == 0 || s.rfind(base, 0) == 0) return true;
            if (s.rfind("/dev/" + base + "p", 0) == 0 || s.rfind("/dev/" + base, 0) == 0) return true;
        }

        return false;
#elif defined(_WIN32)
        std::replace(s.begin(), s.end(), '/', '\\');
        std::string lower = s;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

        wchar_t winDir[MAX_PATH];
        char sysDriveLetter = 'c';
        if (GetWindowsDirectoryW(winDir, MAX_PATH) > 0 && winDir[1] == L':') {
            sysDriveLetter = static_cast<char>(std::tolower(winDir[0]));
        }

        std::string letterStr(1, sysDriveLetter);
        if (lower == letterStr + ":" || lower == letterStr + ":\\" ||
            lower == "\\\\.\\" + letterStr + ":") {
            return true;
        }

        // Query physical disk extents backing the system volume using IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS
        std::string sysDriveDevice = "\\\\.\\" + letterStr + ":";
        HANDLE hVol = CreateFileA(sysDriveDevice.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  NULL, OPEN_EXISTING, 0, NULL);
        if (hVol != INVALID_HANDLE_VALUE) {
            std::vector<uint8_t> extBuf(sizeof(VOLUME_DISK_EXTENTS) + 16 * sizeof(DISK_EXTENT));
            DWORD bytesRet = 0;
            if (DeviceIoControl(hVol, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, NULL, 0,
                                extBuf.data(), static_cast<DWORD>(extBuf.size()), &bytesRet, NULL)) {
                auto* vde = reinterpret_cast<VOLUME_DISK_EXTENTS*>(extBuf.data());
                for (DWORD i = 0; i < vde->NumberOfDiskExtents; ++i) {
                    DWORD diskNum = vde->Extents[i].DiskNumber;
                    std::string physDrive = "\\\\.\\physicaldrive" + std::to_string(diskNum);
                    if (lower == physDrive) {
                        CloseHandle(hVol);
                        return true;
                    }
                }
            } else {
                STORAGE_DEVICE_NUMBER sdn{};
                if (DeviceIoControl(hVol, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0,
                                    &sdn, sizeof(sdn), &bytesRet, NULL)) {
                    std::string physDrive = "\\\\.\\physicaldrive" + std::to_string(sdn.DeviceNumber);
                    if (lower == physDrive) {
                        CloseHandle(hVol);
                        return true;
                    }
                }
            }
            CloseHandle(hVol);
        } else {
            // FAIL-CLOSED on Windows: If volume handle cannot be queried and target is physical drive, protect physicaldrive0
            if (lower.rfind("\\\\.\\physicaldrive", 0) == 0 && sysDriveLetter == 'c') {
                return true;
            }
        }

        if (lower == "\\\\.\\physicaldrive0" && sysDriveLetter == 'c') {
            return true;
        }

        return false;
#else
        return true; // Fail-closed on unsupported platforms
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
