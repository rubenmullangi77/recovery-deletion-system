#pragma once

#include <string>
#include <vector>
#include <mutex>
#include <cstdint>

namespace forensivault {
namespace logging {

/**
 * @brief Represents a recovered file artifact cataloged in a forensic audit record.
 */
struct RecoveredArtifactRecord {
    uint64_t file_id{0};
    std::string filename;
    std::string relative_path;
    std::string file_type;
    std::string extension;
    uint64_t byte_offset{0};
    uint64_t size_bytes{0};
    std::string sha256_hash;
    double confidence_score{0.0};
    std::string confidence_level;
    std::string validation_status;
    std::vector<std::string> reasons;
    std::vector<std::string> warnings;

    std::string toJson() const;
};

/**
 * @brief Represents an individual Chain-of-Custody event.
 */
struct CustodyEvent {
    std::string timestamp_iso;
    std::string action;        // e.g. "EVIDENCE_ACQUIRED", "CUSTODY_TRANSFERRED", "RECOVERY_ANALYSIS"
    std::string custodian;     // Officer / Examiner ID
    std::string location;      // Lab, secure locker, workstation
    std::string notes;

    std::string toJson() const;
};

/**
 * @brief Comprehensive, court-admissible forensic audit entry.
 */
struct AuditEntry {
    uint64_t entry_id{0};
    std::string timestamp_iso;
    std::string case_id;
    std::string evidence_id;
    std::string operation_id;
    std::string operator_name;
    std::string tool_version{"ForensiVault v1.0.0"};
    
    // Operation provenance
    std::string operation_type;      // "FILE_RECOVERY", "DRIVE_SANITIZE", "FILE_ERASE", "EVIDENCE_ACQUIRED"
    std::string source_identifier;   // Path to disk image / physical device
    std::string source_sha256;       // Cryptographic hash of the source disk/image
    std::string method;
    std::string status;              // "SUCCESS", "PARTIAL", "FAILED", "ABORTED", "CONFIRMATION_REQUIRED"
    std::string details;

    // Artifacts & Verification
    std::vector<RecoveredArtifactRecord> recovered_artifacts;
    std::string verification_results;
    std::vector<std::string> warnings_and_errors;

    // Chain of Custody
    std::vector<CustodyEvent> chain_of_custody;

    // Cryptographic Chaining
    std::string previous_hash;
    std::string entry_hash;

    std::string toJson() const;
};

class AuditLogger {
public:
    static AuditLogger& getInstance();

    AuditLogger();
    ~AuditLogger() = default;

    /**
     * @brief Record a simple audit event (backward compatible with file/folder eraser).
     */
    AuditEntry logEvent(const std::string& opType,
                        const std::string& targetPath,
                        const std::string& method,
                        const std::string& status,
                        const std::string& details);

    /**
     * @brief Record a full forensic audit record with complete metadata, artifacts, and custody.
     */
    AuditEntry logForensicOperation(const AuditEntry& draftEntry);

    /**
     * @brief Cryptographically verifies the unbroken SHA-256 hash chain across all entries.
     * @param outBrokenIndex If corrupted, receives the index of the first invalid entry.
     * @return True if 100% intact, false if tampered or invalid.
     */
    bool verifyChain(size_t* outBrokenIndex = nullptr) const;

    /**
     * @brief Get all recorded entries.
     */
    std::vector<AuditEntry> getEntries() const;

    /**
     * @brief Clear all entries (for test resets).
     */
    void clear();

    /**
     * @brief Exports the journal to JSON Lines format.
     */
    bool saveToFile(const std::string& filepath) const;

    /**
     * @brief Loads an audit log from disk and validates chain integrity.
     */
    bool loadFromFile(const std::string& filepath);

    /**
     * @brief Computes SHA-256 hash for an entry given its components.
     */
    static std::string computeEntryHash(const AuditEntry& entry);

    /**
     * @brief Formats current UTC timestamp in ISO 8601 with millisecond precision.
     */
    static std::string currentTimestampIso();

private:
    mutable std::mutex mutex_;
    std::vector<AuditEntry> entries_;
    std::string last_hash_;
};

} // namespace logging
} // namespace forensivault
