#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <functional>

namespace forensivault::api {

enum class DriveSanitizeStandard {
    NIST_800_88_CLEAR,     ///< NIST SP 800-88 Rev 1 Clear: Single pass zero-fill with hardware flush and sampling verification
    DOD_5220_22_M,         ///< DoD 5220.22-M: 3 passes (0x00, 0xFF, Cryptographic PRNG) with sampling verification
    CRYPTO_RANDOM          ///< Cryptographic PRNG random overwrite pass with verification
};

struct StorageDeviceDescriptor {
    std::string deviceId;
    std::string name;
    std::string model;
    std::string serialNumber;
    uint64_t sizeBytes = 0;
    uint32_t sectorSize = 512;
    bool isPhysicalDevice = false;
    bool isSystemOrRootDrive = false;
    bool isSafeToSanitize = false;
    std::string interfaceType;
    std::string mediaType;
    std::vector<std::string> capabilities;
};

struct DriveSanitizeProgress {
    uint64_t bytesProcessed = 0;
    uint64_t totalBytes = 0;
    double percentComplete = 0.0;
    int currentPass = 0;
    int totalPasses = 0;
    double currentSpeedMBps = 0.0;
};

using DriveSanitizeProgressCallback = std::function<void(const DriveSanitizeProgress& progress)>;

struct DriveSanitizeResult {
    bool success = false;
    std::string targetDevice;
    uint64_t totalBytesSanitized = 0;
    int passesCompleted = 0;
    bool verificationPassed = false;
    double durationSeconds = 0.0;
    std::string auditSignature;
    std::string certificateJson;
    std::string errorMessage;
};

/**
 * @brief Public high-level C++ API for storage drive and disk image sanitization.
 */
class DriveSanitizerAPI {
public:
    /**
     * @brief Detects and enumerates all attached system storage devices and drive interfaces.
     */
    static std::vector<StorageDeviceDescriptor> detectDevices();

    /**
     * @brief Inspects a virtual disk image (.img, .dd, .raw) or block device geometry and characteristics.
     */
    static StorageDeviceDescriptor inspectDevice(const std::string& path);

    /**
     * @brief Sanitizes a virtual disk image or unmounted external storage drive in accordance with standards.
     *        Strictly refuses to sanitize root system drives.
     */
    static DriveSanitizeResult sanitize(const std::string& targetPath,
                                        DriveSanitizeStandard standard = DriveSanitizeStandard::NIST_800_88_CLEAR,
                                        DriveSanitizeProgressCallback cb = nullptr);
};

} // namespace forensivault::api
