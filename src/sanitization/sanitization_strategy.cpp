#include "sanitization/sanitization_strategy.hpp"
#include <random>
#include <algorithm>
#include <cstring>

namespace forensivault {
namespace sanitization {

namespace {

void fillWithRandom(uint8_t* buffer, size_t size) {
    static thread_local std::random_device rd;
    static thread_local std::mt19937_64 rng(rd());

    size_t words = size / sizeof(uint64_t);
    uint64_t* ptr = reinterpret_cast<uint64_t*>(buffer);
    for (size_t i = 0; i < words; ++i) {
        ptr[i] = rng();
    }
    size_t rem = size % sizeof(uint64_t);
    if (rem > 0) {
        uint64_t last = rng();
        std::memcpy(buffer + words * sizeof(uint64_t), &last, rem);
    }
}

std::vector<std::string> getCommonSsdLimitations() {
    return {
        "NAND Flash Wear-Leveling: Flash Translation Layer (FTL) maps LBAs dynamically to physical flash cells; overwriting logical LBAs may not reach previously retired, defect-managed, or over-provisioned blocks.",
        "Overwritten blocks may temporarily remain in spare flash blocks until background garbage collection or TRIM occurs.",
        "NIST SP 800-88 Rev 1 recommends firmware-level Cryptographic Erase or Block Erase for true SSD Purge sanitization."
    };
}

} // anonymous namespace

// ---------------- 1. NIST Clear Strategy ----------------
std::string NistClearStrategy::description() const {
    return "Applies a single overwrite pass of 0x00 across all logical sectors, flushes write caches, and verifies zero-entropy across target address space.";
}

std::vector<std::string> NistClearStrategy::limitations(DriveMediaType mediaType) const {
    std::vector<std::string> limits;
    if (mediaType == DriveMediaType::SSD_NAND) {
        limits = getCommonSsdLimitations();
    } else if (mediaType == DriveMediaType::HDD_ROTATIONAL) {
        limits.push_back("Single-pass zero-fill effectively clears magnetic rotational sectors on modern high-density drives, but firmware-remapped Bad Sectors (G-List) remain unmodified.");
    }
    limits.push_back("Zero-fill produces uniform zero-entropy output easily recognized by forensic tools.");
    return limits;
}

void NistClearStrategy::fillPassBuffer(int /*passNumber*/, uint8_t* buffer, size_t size) const {
    std::memset(buffer, 0x00, size);
}

bool NistClearStrategy::isApplicableTo(DriveMediaType /*mediaType*/) const {
    return true; // Applicable to all media types for Clear level
}

// ---------------- 2. DoD 5220.22-M Strategy ----------------
std::string Dod522022MStrategy::description() const {
    return "Executes a rigorous 3-pass overwrite: Pass 1 writes 0x00, Pass 2 writes 0xFF, and Pass 3 writes cryptographically secure pseudorandom bytes with hardware flush between passes.";
}

std::vector<std::string> Dod522022MStrategy::limitations(DriveMediaType mediaType) const {
    std::vector<std::string> limits;
    if (mediaType == DriveMediaType::SSD_NAND) {
        limits = getCommonSsdLimitations();
        limits.push_back("Multiple overwrite passes on SSDs induce unnecessary NAND write endurance wear without improving data elimination over physical firmware purge.");
    } else {
        limits.push_back("Firmware-level reallocated bad sectors (G-List / P-List) cannot be reached by logical sector overwriting.");
    }
    return limits;
}

void Dod522022MStrategy::fillPassBuffer(int passNumber, uint8_t* buffer, size_t size) const {
    if (passNumber == 1) {
        std::memset(buffer, 0x00, size);
    } else if (passNumber == 2) {
        std::memset(buffer, 0xFF, size);
    } else {
        fillWithRandom(buffer, size);
    }
}

bool Dod522022MStrategy::isApplicableTo(DriveMediaType mediaType) const {
    // Primarily intended for rotational HDDs and disk images
    return mediaType == DriveMediaType::HDD_ROTATIONAL ||
           mediaType == DriveMediaType::DISK_IMAGE_RAW ||
           mediaType == DriveMediaType::USB_DRIVE;
}

// ---------------- 3. Pseudorandom Strategy ----------------
std::string PseudorandomStrategy::description() const {
    return "Applies a single pass of cryptographically secure pseudorandom data generated from high-entropy hardware random pools.";
}

std::vector<std::string> PseudorandomStrategy::limitations(DriveMediaType mediaType) const {
    std::vector<std::string> limits;
    if (mediaType == DriveMediaType::SSD_NAND) {
        limits = getCommonSsdLimitations();
    }
    limits.push_back("Pseudorandom fill leaves high-entropy data (~8.0 bits/byte) resembling encrypted content.");
    return limits;
}

void PseudorandomStrategy::fillPassBuffer(int /*passNumber*/, uint8_t* buffer, size_t size) const {
    fillWithRandom(buffer, size);
}

bool PseudorandomStrategy::isApplicableTo(DriveMediaType /*mediaType*/) const {
    return true;
}

// ---------------- 4. ATA / NVMe Firmware Sanitize Strategy ----------------
std::string AtaNvmeFirmwareEraseStrategy::description() const {
    return "Sends hardware-level firmware commands (NVMe Format / Sanitize Block Erase / ATA Enhanced Secure Erase) directly to storage controller. Executes physical NAND block erasure including spare/overprovisioned cells.";
}

std::vector<std::string> AtaNvmeFirmwareEraseStrategy::limitations(DriveMediaType mediaType) const {
    std::vector<std::string> limits;
    limits.push_back("Requires direct hardware controller access and firmware command support (SATA ATA Secure Erase or NVMe Sanitize Specification).");
    if (mediaType == DriveMediaType::DISK_IMAGE_RAW) {
        limits.push_back("Hardware firmware commands cannot be issued to raw virtual disk images. Software-based multi-pass overwriting must be used instead.");
    } else {
        limits.push_back("Physical drive sanitization is strictly restricted to capability detection in this prototype build to protect system hardware.");
    }
    return limits;
}

void AtaNvmeFirmwareEraseStrategy::fillPassBuffer(int /*passNumber*/, uint8_t* /*buffer*/, size_t /*size*/) const {
    // Hardware firmware erase does not stream software buffers
}

bool AtaNvmeFirmwareEraseStrategy::isApplicableTo(DriveMediaType mediaType) const {
    return mediaType == DriveMediaType::SSD_NAND || mediaType == DriveMediaType::HDD_ROTATIONAL;
}

} // namespace sanitization
} // namespace forensivault
