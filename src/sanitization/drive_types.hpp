#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <ostream>

namespace forensivault {
namespace sanitization {

enum class DriveMediaType {
    DISK_IMAGE_RAW,    // Virtual raw disk image (.img, .dd, .raw)
    HDD_ROTATIONAL,    // Magnetic rotational hard disk drive
    SSD_NAND,          // Solid-state drive (NAND flash)
    USB_DRIVE,         // USB thumb drive / external flash drive
    MEMORY_CARD_SD     // SD / microSD memory card
};

inline std::ostream& operator<<(std::ostream& os, DriveMediaType type) {
    switch (type) {
        case DriveMediaType::DISK_IMAGE_RAW: return os << "Raw Disk Image (.img/.dd)";
        case DriveMediaType::HDD_ROTATIONAL: return os << "Hard Disk Drive (Rotational Magnetic)";
        case DriveMediaType::SSD_NAND:       return os << "Solid-State Drive (NAND Flash)";
        case DriveMediaType::USB_DRIVE:      return os << "USB Flash Storage";
        case DriveMediaType::MEMORY_CARD_SD: return os << "Memory Card (SD/MMC)";
        default:                             return os << "UNKNOWN";
    }
}

enum class DriveInterface {
    VIRTUAL_IMAGE,
    SATA,
    NVME,
    USB,
    SDIO,
    UNKNOWN
};

inline std::ostream& operator<<(std::ostream& os, DriveInterface iface) {
    switch (iface) {
        case DriveInterface::VIRTUAL_IMAGE: return os << "Virtual / Disk Image";
        case DriveInterface::SATA:          return os << "SATA / AHCI";
        case DriveInterface::NVME:          return os << "NVMe (PCIe)";
        case DriveInterface::USB:           return os << "USB Mass Storage";
        case DriveInterface::SDIO:          return os << "SDIO / Card Reader";
        default:                            return os << "UNKNOWN";
    }
}

struct DriveProperties {
    std::string target_path;
    std::string device_identifier;
    std::string model_name;
    std::string serial_number;
    DriveMediaType media_type{DriveMediaType::DISK_IMAGE_RAW};
    DriveInterface interface_type{DriveInterface::VIRTUAL_IMAGE};

    uint64_t total_bytes{0};
    uint32_t sector_size{512};
    uint64_t total_sectors{0};

    // Hardware firmware capabilities
    bool supports_trim{false};
    bool supports_nvme_format{false};
    bool supports_ata_secure_erase{false};
    bool supports_sanitize_crypto{false};

    bool is_physical_device{false};
    bool is_safe_to_sanitize{true}; // False for physical system drives

    std::vector<std::string> capabilities;
    std::vector<std::string> hardware_limitations;
};

struct SanitizationReport {
    std::string target_path;
    DriveMediaType media_type{DriveMediaType::DISK_IMAGE_RAW};
    std::string strategy_name;
    std::string strategy_standard;
    
    // Cryptographic proof of transformation
    std::string pre_wipe_sha256;
    std::string post_wipe_sha256;

    // Timestamps
    std::string start_timestamp_iso;
    std::string end_timestamp_iso;
    double duration_milliseconds{0.0};

    // Verification metrics
    bool verified{false};
    double match_rate_percentage{0.0};
    double measured_entropy{0.0};
    uint64_t total_bytes_sanitized{0};
    int passes_completed{0};

    uint64_t audit_entry_id{0};
    std::string audit_entry_hash;

    std::vector<std::string> limitations_disclosed;
    std::string summary;
};

} // namespace sanitization
} // namespace forensivault
