#pragma once

#include "core/disk_image_reader.hpp"
#include "filesystem/fs_analyzer.hpp"
#include "carving/file_carver.hpp"
#include "carving/confidence_scorer.hpp"
#include <memory>
#include <string>
#include <vector>

namespace forensivault {
namespace logging {
    struct AuditEntry;
}

namespace recovery {

struct CaseContext {
    std::string case_id;
    std::string evidence_id;
    std::string operation_id;
    std::string operator_name;
};

struct RecoveryReport {
    bool fs_detected{false};
    filesystem::FsType fs_type{filesystem::FsType::UNKNOWN};
    filesystem::FsVolumeInfo volume_info;
    
    // Filesystem recovery results (intact and deleted candidate entries)
    std::vector<filesystem::FsFileRecord> filesystem_active_files;
    std::vector<filesystem::FsFileRecord> filesystem_deleted_files;

    // Raw file carving results (unallocated or missing metadata fallback)
    std::vector<carving::CarvedFile> raw_carved_files;

    // Evidence provenance
    std::string evidence_image_path;
    std::string evidence_pre_hash;
    std::string evidence_post_hash;
    bool evidence_unmodified{true};

    // Forensic audit entry generated for this recovery
    uint64_t audit_entry_id{0};
    std::string audit_entry_hash;

    size_t total_recovered_count() const {
        return filesystem_active_files.size() + filesystem_deleted_files.size() + raw_carved_files.size();
    }
};

class RecoveryEngine {
public:
    RecoveryEngine();
    ~RecoveryEngine() = default;

    // Execute full recovery pipeline: probe FS, extract metadata, fall back to carving
    RecoveryReport runRecovery(core::DiskImageReader& reader,
                               const std::string& outputDir = "",
                               const CaseContext& ctx = CaseContext{});

    // Create appropriate analyzer for a given image
    std::unique_ptr<filesystem::FilesystemAnalyzer> detectFilesystem(core::DiskImageReader& reader, uint64_t partitionStartSector = 0);

};

} // namespace recovery
} // namespace forensivault
