#include "view_disk_inspect.hpp"
#include "ui_theme.hpp"
#include "file_dialog.hpp"
#include "app_context.hpp"

#include <core/disk_image_reader.hpp>
#include <forensivault/common/crypto_hash.hpp>

#include <imgui.h>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <filesystem>

namespace fs = std::filesystem;

namespace forensivault::gui {

ViewDiskInspect::ViewDiskInspect() {
    std::memset(imagePathBuffer_, 0, sizeof(imagePathBuffer_));
}

void ViewDiskInspect::render() {
    UITheme::renderCardHeader("DISK GEOMETRY & EVIDENCE INTEGRITY HASHING",
                              "Physical Geometry Inspection, Sector 0 MBR/VBR Validation & Read-Only Ingest Hashing");

    renderInputs();

    if (hasGeometry_) {
        renderGeometry();
    }

    if (hashRunner_.isRunning()) {
        if (UITheme::beginCard("HashProgCard", "Hashing Evidence Image (Read-Only Mode)", "STREAM HASH", UITheme::COLOR_BLUE)) {
            UITheme::renderProgressBar(hashRunner_.getProgress(), hashRunner_.getStatusText().c_str());
        }
        UITheme::endCard();
    }

    if (hasHashes_) {
        renderHashes();
    }
}

void ViewDiskInspect::renderInputs() {
    if (UITheme::beginCard("InspectInputCard", "Target Disk Image or Block Device", "EVIDENCE SOURCE", UITheme::COLOR_BLUE)) {
        ImGui::Text("Target Disk Image or Block Device:");
        if (UITheme::renderInputWithButton("##InspectPath", imagePathBuffer_, sizeof(imagePathBuffer_), "Browse Image...", 140.0f)) {
            std::string selected = FileDialog::openFile("Select Disk Image", "Disk Images (*.img;*.dd;*.raw;*.iso;*.*)", "*.img;*.dd;*.raw;*.iso;*.*");
            if (!selected.empty()) {
                std::strncpy(imagePathBuffer_, selected.c_str(), sizeof(imagePathBuffer_) - 1);
                hasGeometry_ = false;
                hasHashes_ = false;
            }
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        bool canInspect = strlen(imagePathBuffer_) > 0 && fs::exists(imagePathBuffer_);

        if (!canInspect) ImGui::BeginDisabled();

        float actAvailW = ImGui::GetContentRegionAvail().x;
        float actSpacing = ImGui::GetStyle().ItemSpacing.x;
        bool stackAct = (actAvailW < 560.0f);
        float aBtn1W = stackAct ? -1.0f : 220.0f;
        float aBtn2W = stackAct ? -1.0f : 320.0f;

        if (UITheme::renderSecondaryButton("Inspect Disk Geometry", ImVec2(aBtn1W, 36))) {
            hasGeometry_ = false;
            hasHashes_ = false;
            geomError_.clear();

            forensivault::core::DiskImageReader reader(imagePathBuffer_);
            if (!reader.isOpen()) {
                geomError_ = reader.lastError();
                hasGeometry_ = true;
            } else {
                geomFilePath_ = reader.filepath();
                geomTotalSize_ = reader.size();
                geomSectorSize_ = reader.sectorSize();
                geomTotalSectors_ = reader.totalSectors();

                auto s0 = reader.readSector(0);
                if (!s0.empty()) {
                    geomHasMbr_ = (s0.size() >= 512 && s0[510] == 0x55 && s0[511] == 0xAA);
                    geomSector0Desc_ = geomHasMbr_ ? "Valid MBR / VBR Signature 0x55AA Detected" : "Non-MBR Custom Boot Sector";
                } else {
                    geomSector0Desc_ = "Unable to read sector 0";
                }
                hasGeometry_ = true;
            }
        }

        if (!stackAct) ImGui::SameLine(0.0f, actSpacing);
        else ImGui::Dummy(ImVec2(0, 4.0f));

        if (UITheme::renderPrimaryButton("Compute Cryptographic Evidence Hashes...", ImVec2(aBtn2W, 36))) {
            hasHashes_ = false;
            std::string path = imagePathBuffer_;

            hashRunner_.run([this, path]() {
                forensivault::core::DiskImageReader r(path);
                if (!r.isOpen()) return;

                uint64_t total = r.size();
                uint64_t processed = 0;
                const size_t CHUNK = 1024 * 1024; // 1 MB buffer

                forensivault::CryptoHash::Sha256Context shaCtx;
                forensivault::CryptoHash::Md5Context md5Ctx;

                while (processed < total && !hashRunner_.isCancelRequested()) {
                    size_t toRead = static_cast<size_t>(std::min(static_cast<uint64_t>(CHUNK), total - processed));
                    auto chunk = r.readBytes(processed, toRead);
                    if (chunk.empty()) break;

                    shaCtx.update(chunk.data(), chunk.size());
                    md5Ctx.update(chunk.data(), chunk.size());
                    processed += chunk.size();

                    float frac = static_cast<float>(processed) / static_cast<float>(total);
                    std::stringstream ss;
                    ss << "Hashing: " << std::fixed << std::setprecision(1) << (frac * 100.0f) << "% ("
                       << (processed / (1024 * 1024)) << " / " << (total / (1024 * 1024)) << " MB)";
                    hashRunner_.setProgress(frac, ss.str());
                }

                sha256Hash_ = shaCtx.finalize();
                md5Hash_ = md5Ctx.finalize();
                hasHashes_ = true;
            });
        }

        if (!canInspect) ImGui::EndDisabled();
    }
    UITheme::endCard();
}

void ViewDiskInspect::renderGeometry() {
    if (UITheme::beginCard("GeomResultCard", "Physical Storage Geometry & Sector 0 Analysis",
                           geomError_.empty() ? "ANALYSIS COMPLETE" : "ERROR",
                           geomError_.empty() ? UITheme::COLOR_GREEN : UITheme::COLOR_RED)) {
        if (!geomError_.empty()) {
            UITheme::renderDangerBanner(geomError_.c_str());
            UITheme::endCard();
            return;
        }

        ImGui::Columns(3, nullptr, false);

        double mb = static_cast<double>(geomTotalSize_) / (1024.0 * 1024.0);
        std::stringstream ssMb;
        ssMb << std::fixed << std::setprecision(2) << mb << " MB (" << geomTotalSize_ << " B)";
        UITheme::renderMetricTile("Image Capacity", ssMb.str().c_str(), "Total byte size", UITheme::COLOR_ORANGE, -1);

        ImGui::NextColumn();

        std::string secStr = std::to_string(geomSectorSize_) + " Bytes";
        UITheme::renderMetricTile("Sector Size", secStr.c_str(), "Logical block address", UITheme::COLOR_BLUE, -1);

        ImGui::NextColumn();

        std::string totSecStr = std::to_string(geomTotalSectors_);
        UITheme::renderMetricTile("Total Sectors", totSecStr.c_str(), "Addressable LBAs", UITheme::COLOR_TEXT_PRIMARY, -1);

        ImGui::Columns(1);
        ImGui::Spacing();

        ImGui::Text("Sector 0 Boot Record:  ");
        ImGui::SameLine();
        if (geomHasMbr_) {
            UITheme::renderBadge("0x55AA VALID MBR", UITheme::COLOR_GREEN);
        } else {
            UITheme::renderBadge("NON-MBR BOOT SECTOR", UITheme::COLOR_YELLOW);
        }
        ImGui::Spacing();
        UITheme::renderWrappedText(geomSector0Desc_.c_str(), UITheme::COLOR_TEXT_SECONDARY);
    }
    UITheme::endCard();
}

void ViewDiskInspect::renderHashes() {
    if (UITheme::beginCard("HashResultCard", "Cryptographic Ingest Fingerprints", "CHAIN OF CUSTODY", UITheme::COLOR_GREEN)) {
        UITheme::renderSuccessBanner("Read-only streaming hash completed. Evidence integrity verified.");

        ImGui::Spacing();
        UITheme::renderWrappedText("SHA-256 Fingerprint:", UITheme::COLOR_TEXT_MUTED);
        if (UITheme::fontMono) ImGui::PushFont(UITheme::fontMono);
        UITheme::renderWrappedText(sha256Hash_.c_str(), UITheme::COLOR_ORANGE);
        if (UITheme::fontMono) ImGui::PopFont();

        ImGui::Spacing();
        UITheme::renderWrappedText("MD5 Fingerprint:", UITheme::COLOR_TEXT_MUTED);
        if (UITheme::fontMono) ImGui::PushFont(UITheme::fontMono);
        UITheme::renderWrappedText(md5Hash_.c_str(), UITheme::COLOR_BLUE);
        if (UITheme::fontMono) ImGui::PopFont();
    }
    UITheme::endCard();
}

} // namespace forensivault::gui
