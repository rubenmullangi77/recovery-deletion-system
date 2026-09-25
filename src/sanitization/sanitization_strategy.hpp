#pragma once

#include "sanitization/drive_types.hpp"
#include <string>
#include <vector>
#include <memory>
#include <cstdint>

namespace forensivault {
namespace sanitization {

class SanitizationStrategy {
public:
    virtual ~SanitizationStrategy() = default;

    virtual std::string name() const = 0;
    virtual std::string standard() const = 0;
    virtual std::string description() const = 0;
    virtual std::vector<std::string> limitations(DriveMediaType mediaType) const = 0;
    virtual int totalPasses() const = 0;
    virtual void fillPassBuffer(int passNumber, uint8_t* buffer, size_t size) const = 0;
    virtual bool isApplicableTo(DriveMediaType mediaType) const = 0;
    virtual bool isHardwareFirmwareCommand() const { return false; }
};

// 1. NIST SP 800-88 Rev 1 Clear Strategy (Single-pass 0x00)
class NistClearStrategy : public SanitizationStrategy {
public:
    std::string name() const override { return "NIST SP 800-88 Rev 1 Clear"; }
    std::string standard() const override { return "NIST SP 800-88 Rev 1 Section 2.4 (Clear)"; }
    std::string description() const override;
    std::vector<std::string> limitations(DriveMediaType mediaType) const override;
    int totalPasses() const override { return 1; }
    void fillPassBuffer(int passNumber, uint8_t* buffer, size_t size) const override;
    bool isApplicableTo(DriveMediaType mediaType) const override;
};

// 2. DoD 5220.22-M 3-Pass Strategy (0x00, 0xFF, Random)
class Dod522022MStrategy : public SanitizationStrategy {
public:
    std::string name() const override { return "DoD 5220.22-M (3-Pass Overwrite)"; }
    std::string standard() const override { return "DoD 5220.22-M (NISPOM)"; }
    std::string description() const override;
    std::vector<std::string> limitations(DriveMediaType mediaType) const override;
    int totalPasses() const override { return 3; }
    void fillPassBuffer(int passNumber, uint8_t* buffer, size_t size) const override;
    bool isApplicableTo(DriveMediaType mediaType) const override;
};

// 3. Single-Pass Pseudorandom Strategy
class PseudorandomStrategy : public SanitizationStrategy {
public:
    std::string name() const override { return "Pseudorandom Overwrite (1-Pass)"; }
    std::string standard() const override { return "NIST SP 800-88 / BSI Baseline"; }
    std::string description() const override;
    std::vector<std::string> limitations(DriveMediaType mediaType) const override;
    int totalPasses() const override { return 1; }
    void fillPassBuffer(int passNumber, uint8_t* buffer, size_t size) const override;
    bool isApplicableTo(DriveMediaType mediaType) const override;
};

// 4. Hardware Firmware Sanitize Strategy (for reporting physical SSD/NVMe/ATA capabilities)
class AtaNvmeFirmwareEraseStrategy : public SanitizationStrategy {
public:
    std::string name() const override { return "Hardware Firmware Sanitize (NVMe / ATA Purge)"; }
    std::string standard() const override { return "NIST SP 800-88 Rev 1 Purge (Firmware / Cryptographic Erase)"; }
    std::string description() const override;
    std::vector<std::string> limitations(DriveMediaType mediaType) const override;
    int totalPasses() const override { return 0; }
    void fillPassBuffer(int passNumber, uint8_t* buffer, size_t size) const override;
    bool isApplicableTo(DriveMediaType mediaType) const override;
    bool isHardwareFirmwareCommand() const override { return true; }
};

} // namespace sanitization
} // namespace forensivault
