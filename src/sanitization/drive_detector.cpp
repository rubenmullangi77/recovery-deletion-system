#include "sanitization/drive_detector.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <algorithm>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winioctl.h>
#endif

namespace fs = std::filesystem;

namespace forensivault {
namespace sanitization {

namespace {

#if defined(__linux__)
std::string readFileTrim(const std::string& path) {
    std::ifstream ifs(path);
    if (!ifs) return "";
    std::string s;
    std::getline(ifs, s);
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

bool isLinuxDeviceMountedAsRootOrBoot(const std::string& devName) {
    std::ifstream ifs("/proc/mounts");
    if (!ifs) return false;
    std::string line;
    while (std::getline(ifs, line)) {
        std::istringstream iss(line);
        std::string dev, mountPoint;
        if (iss >> dev >> mountPoint) {
            // Check if dev matches or contains devName, e.g. /dev/nvme0n1p2 contains nvme0n1
            if (dev.find(devName) != std::string::npos) {
                if (mountPoint == "/" || mountPoint == "/boot" || mountPoint == "/boot/efi" || mountPoint == "/etc") {
                    return true;
                }
            }
        }
    }
    return false;
}
#endif

} // anonymous namespace

DriveProperties DriveDetector::detectImage(
    const std::string& imagePath,
    DriveMediaType simulatedType) {

    DriveProperties props;
    props.target_path = imagePath;
    props.media_type = simulatedType;
    props.interface_type = DriveInterface::VIRTUAL_IMAGE;
    props.is_physical_device = false;
    props.is_safe_to_sanitize = true;

    std::error_code ec;
    if (!fs::exists(imagePath, ec) || !fs::is_regular_file(imagePath, ec)) {
        props.is_safe_to_sanitize = false;
        props.hardware_limitations.push_back("File does not exist or is not a regular file.");
        return props;
    }

    uint64_t fileSize = fs::file_size(imagePath, ec);
    if (ec) {
        props.is_safe_to_sanitize = false;
        props.hardware_limitations.push_back("Could not read file size: " + ec.message());
        return props;
    }

    props.total_bytes = fileSize;
    props.sector_size = 512;
    props.total_sectors = fileSize / props.sector_size;
    props.device_identifier = "RAW_IMAGE://" + fs::absolute(imagePath).string();
    props.model_name = "ForensiVault Virtual Image Target (" + fs::path(imagePath).filename().string() + ")";
    props.serial_number = "FV-VIRT-" + std::to_string(fileSize);

    // Read Sector 0 to check partition signature
    std::ifstream ifs(imagePath, std::ios::binary);
    if (ifs) {
        std::vector<uint8_t> sec0(512);
        ifs.read(reinterpret_cast<char*>(sec0.data()), 512);
        if (ifs.gcount() >= 512) {
            bool has55AA = (sec0[510] == 0x55 && sec0[511] == 0xAA);
            if (has55AA) {
                props.capabilities.push_back("Partition Table / Boot Sector Signature Verified (0x55AA)");
            }
        }
    }

    props.capabilities.push_back("Logical Sector Read/Write Overwrite Supported");
    props.capabilities.push_back("Full-Image Cryptographic Pre/Post Hash Verification Supported");
    props.capabilities.push_back("Sector-by-Sector Shannon Entropy Verification Supported");

    if (simulatedType == DriveMediaType::SSD_NAND) {
        props.hardware_limitations.push_back(
            "Simulated SSD target: Real physical SSDs have overprovisioned spare NAND blocks inaccessible via logical sector overwriting.");
        props.supports_trim = true;
    } else if (simulatedType == DriveMediaType::USB_DRIVE || simulatedType == DriveMediaType::MEMORY_CARD_SD) {
        props.hardware_limitations.push_back(
            "Simulated Flash target: Flash memory controllers use Wear-Leveling algorithms that map logical blocks dynamically.");
    }

    return props;
}

std::vector<DriveProperties> DriveDetector::detectPhysicalDevices() {
    std::vector<DriveProperties> devices;

#if defined(__linux__)
    std::error_code ec;
    if (fs::exists("/sys/block", ec)) {
        for (const auto& entry : fs::directory_iterator("/sys/block", ec)) {
            std::string name = entry.path().filename().string();
            // Ignore virtual loop and zram devices
            if (name.rfind("loop", 0) == 0 || name.rfind("ram", 0) == 0 || name.rfind("zram", 0) == 0) {
                continue;
            }

            DriveProperties dev;
            dev.is_physical_device = true;
            dev.device_identifier = "/dev/" + name;
            dev.target_path = "/dev/" + name;

            // Size in 512-byte sectors from sysfs
            std::string sizeStr = readFileTrim(entry.path().string() + "/size");
            uint64_t sectors = 0;
            if (!sizeStr.empty()) {
                try { sectors = std::stoull(sizeStr); } catch (...) {}
            }

            // Sector size
            std::string secSzStr = readFileTrim(entry.path().string() + "/queue/logical_block_size");
            if (secSzStr.empty()) secSzStr = readFileTrim(entry.path().string() + "/queue/hw_sector_size");
            uint32_t sectorSize = 512;
            if (!secSzStr.empty()) {
                try { sectorSize = static_cast<uint32_t>(std::stoul(secSzStr)); } catch (...) {}
            }
            if (sectorSize == 0) sectorSize = 512;

            dev.sector_size = sectorSize;
            dev.total_sectors = sectors;
            dev.total_bytes = sectors * 512;

            // Model name
            std::string model = readFileTrim(entry.path().string() + "/device/model");
            if (model.empty()) model = readFileTrim(entry.path().string() + "/device/name");
            if (model.empty()) model = "Physical Storage Device (" + name + ")";
            dev.model_name = model;

            // Serial number
            std::string serial = readFileTrim(entry.path().string() + "/device/serial");
            if (serial.empty()) serial = readFileTrim(entry.path().string() + "/device/wwid");
            if (serial.empty()) serial = "DEV-" + name;
            dev.serial_number = serial;

            // Rotational flag
            std::string rotStr = readFileTrim(entry.path().string() + "/queue/rotational");
            bool isRotational = (rotStr == "1");

            // Interface & Media Classification
            if (name.rfind("nvme", 0) == 0) {
                dev.interface_type = DriveInterface::NVME;
                dev.media_type = DriveMediaType::SSD_NAND;
                dev.supports_trim = true;
                dev.supports_nvme_format = true;
                dev.supports_sanitize_crypto = true;
                dev.capabilities.push_back("Hardware NVMe Sanitize Specification (Crypto Erase / Block Erase)");
                dev.capabilities.push_back("NVMe Format (Namespace Formatting / Secure Erase)");
                dev.capabilities.push_back("TRIM / Deallocate (Dataset Management)");
            } else if (name.rfind("mmcblk", 0) == 0) {
                dev.interface_type = DriveInterface::USB;
                dev.media_type = DriveMediaType::MEMORY_CARD_SD;
                dev.capabilities.push_back("SD / MMC Block Erase Supported");
            } else {
                std::string removableStr = readFileTrim(entry.path().string() + "/removable");
                bool isRemovable = (removableStr == "1");
                if (isRemovable) {
                    dev.interface_type = DriveInterface::USB;
                    dev.media_type = DriveMediaType::USB_DRIVE;
                    dev.capabilities.push_back("USB Mass Storage Clear / Overwriting Supported");
                } else {
                    dev.interface_type = DriveInterface::SATA;
                    dev.media_type = isRotational ? DriveMediaType::HDD_ROTATIONAL : DriveMediaType::SSD_NAND;
                    if (dev.media_type == DriveMediaType::SSD_NAND) {
                        dev.supports_trim = true;
                        dev.capabilities.push_back("ATA Secure Erase / Sanitize Block Erase");
                        dev.capabilities.push_back("TRIM / UNMAP supported");
                    } else {
                        dev.capabilities.push_back("NIST SP 800-88 Multi-Pass Overwriting Supported");
                        dev.capabilities.push_back("DoD 5220.22-M 3-Pass Overwriting Supported");
                    }
                }
            }

            // Root / System Drive Safety Check
            bool isRoot = isLinuxDeviceMountedAsRootOrBoot(name);
            dev.is_safe_to_sanitize = !isRoot;
            if (isRoot) {
                dev.hardware_limitations.push_back("CRITICAL SYSTEM PROTECTION: Device hosts active root ('/') or boot filesystem.");
            }
            if (dev.media_type == DriveMediaType::SSD_NAND) {
                dev.hardware_limitations.push_back("Flash Translation Layer (FTL) wear leveling may cause overprovisioned blocks to retain data.");
            }

            devices.push_back(dev);
        }
    }
#elif defined(_WIN32)
    for (uint32_t diskNum = 0; diskNum < 16; ++diskNum) {
        std::string diskPath = "\\\\.\\PhysicalDrive" + std::to_string(diskNum);
        std::wstring wDiskPath(diskPath.begin(), diskPath.end());
        HANDLE hDisk = CreateFileW(
            wDiskPath.c_str(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );
        if (hDisk == INVALID_HANDLE_VALUE) continue;

        DriveProperties dev;
        dev.is_physical_device = true;
        dev.device_identifier = diskPath;
        dev.target_path = diskPath;

        DISK_GEOMETRY_EX geomEx = {0};
        DWORD bytesRet = 0;
        if (DeviceIoControl(hDisk, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0, &geomEx, sizeof(geomEx), &bytesRet, NULL)) {
            dev.total_bytes = geomEx.DiskSize.QuadPart;
            dev.sector_size = geomEx.Geometry.BytesPerSector > 0 ? geomEx.Geometry.BytesPerSector : 512;
            dev.total_sectors = dev.total_bytes / dev.sector_size;
        }

        STORAGE_PROPERTY_QUERY propQuery;
        memset(&propQuery, 0, sizeof(propQuery));
        propQuery.PropertyId = StorageDeviceProperty;
        propQuery.QueryType = PropertyStandardQuery;
        std::vector<uint8_t> descBuf(2048, 0);
        if (DeviceIoControl(hDisk, IOCTL_STORAGE_QUERY_PROPERTY, &propQuery, sizeof(propQuery), descBuf.data(), static_cast<DWORD>(descBuf.size()), &bytesRet, NULL)) {
            auto* desc = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(descBuf.data());
            if (desc->BusType == 17) {
                dev.interface_type = DriveInterface::NVME;
                dev.media_type = DriveMediaType::SSD_NAND;
            } else if (desc->BusType == 7) {
                dev.interface_type = DriveInterface::USB;
                dev.media_type = DriveMediaType::USB_DRIVE;
            } else {
                dev.interface_type = DriveInterface::SATA;
                dev.media_type = (desc->RemovableMedia != FALSE) ? DriveMediaType::USB_DRIVE : DriveMediaType::SSD_NAND;
            }

            if (desc->ProductIdOffset > 0 && desc->ProductIdOffset < bytesRet) {
                dev.model_name = reinterpret_cast<const char*>(descBuf.data() + desc->ProductIdOffset);
            } else {
                dev.model_name = "Physical Drive " + std::to_string(diskNum);
            }
            if (desc->SerialNumberOffset > 0 && desc->SerialNumberOffset < bytesRet) {
                dev.serial_number = reinterpret_cast<const char*>(descBuf.data() + desc->SerialNumberOffset);
            } else {
                dev.serial_number = "DRIVE-" + std::to_string(diskNum);
            }
        }

        if (diskNum == 0) {
            dev.is_safe_to_sanitize = false;
            dev.hardware_limitations.push_back("CRITICAL SYSTEM PROTECTION: Primary system drive (PhysicalDrive0).");
        } else {
            dev.is_safe_to_sanitize = true;
        }

        dev.capabilities.push_back("Physical Storage Sector Overwrite Supported");
        CloseHandle(hDisk);
        devices.push_back(dev);
    }
#endif

    // Fallback if no devices found
    if (devices.empty()) {
        DriveProperties fallback;
        fallback.device_identifier = "PHYSICAL_DRIVES_UNAVAILABLE";
        fallback.target_path = "None";
        fallback.model_name = "No accessible physical storage devices detected";
        fallback.is_physical_device = true;
        fallback.is_safe_to_sanitize = false;
        devices.push_back(fallback);
    }

    return devices;
}

} // namespace sanitization
} // namespace forensivault
