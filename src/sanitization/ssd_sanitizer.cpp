#include "sanitization/ssd_sanitizer.hpp"

namespace forensivault {
namespace sanitization {

SsdSanitizationCapabilityReport SSDSanitizer::evaluateCapabilities(const DriveProperties& props) {
    SsdSanitizationCapabilityReport rep;
    rep.device_identifier = props.device_identifier;
    rep.supports_nvme_crypto_erase = props.supports_sanitize_crypto;
    rep.supports_nvme_block_erase = props.supports_nvme_format;
    rep.supports_ata_enhanced_erase = props.supports_ata_secure_erase;
    rep.supports_trim_deallocate = props.supports_trim;
    rep.software_overwrite_sufficient = false; // NEVER sufficient on physical SSDs

    rep.recommended_method = (props.interface_type == DriveInterface::NVME)
        ? "NIST SP 800-88 Purge: NVMe Sanitize Cryptographic Erase / Block Erase"
        : "NIST SP 800-88 Purge: ATA Enhanced Secure Erase";

    rep.critical_disclosures = {
        "Flash Translation Layer (FTL) Mapping: The host writes to Logical Block Addresses (LBAs). The SSD controller dynamically maps LBAs to physical NAND blocks. Overwriting an LBA simply maps it to a new physical block, leaving original data in the previous block until garbage-collected.",
        "Overprovisioning (OP) & Spare Blocks: Up to 7-28% of physical flash memory is reserved by the controller for defect management and wear-leveling. These spare blocks are completely invisible and inaccessible to host software LBA writes.",
        "NAND Write Endurance: Multi-pass software overwriting (such as DoD 3-pass or Gutmann 35-pass) causes severe NAND wear without providing any additional forensic security."
    };

    rep.unverifiable_aspects = {
        "Retired Bad Blocks: Flash blocks with uncorrectable bit errors (ECC failures) are permanently taken offline by the controller. They retain original plaintext data and cannot be erased via host commands.",
        "Controller Cache & Read Buffers: Internal volatile and non-volatile controller SRAM/DRAM buffers cannot be inspected or verified by OS software."
    };

    return rep;
}

std::vector<std::string> SSDSanitizer::getForensicConsiderations() {
    return {
        "NIST SP 800-88 Rev 1 explicitly distinguishes between 'Clear' (logical overwrite) and 'Purge' (firmware cryptographic/block erase).",
        "For Solid-State Drives, Purge via NVMe Format / Cryptographic Erase or ATA Secure Erase is the only standard-compliant sanitization method.",
        "Software-level single-pass zero overwrite is classified as 'Clear' only, and should never be represented as eliminating physical NAND forensic evidence."
    };
}

std::unique_ptr<SanitizationStrategy> SSDSanitizer::getRecommendedStrategy() {
    return std::make_unique<AtaNvmeFirmwareEraseStrategy>();
}

} // namespace sanitization
} // namespace forensivault
