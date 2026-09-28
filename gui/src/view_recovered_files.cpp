#include "view_recovered_files.hpp"
#include "ui_theme.hpp"
#include "app_context.hpp"
#include "file_dialog.hpp"

#include <imgui.h>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

namespace forensivault::gui {

ViewRecoveredFiles::ViewRecoveredFiles() {
    std::memset(searchFilterBuffer_, 0, sizeof(searchFilterBuffer_));
}

void ViewRecoveredFiles::render() {
    UITheme::renderCardHeader("RECOVERED FILES & EVIDENCE ARTIFACT BROWSER",
                              "Unified Registry of Files Carved from Raw Streams and Reconstructed from Filesystem Metadata");

    auto& ctx = AppContext::getInstance();

    std::vector<UnifiedRecoveredFile> filesCopy;
    {
        std::lock_guard<std::mutex> lock(ctx.registryMutex);
        filesCopy = ctx.recoveredFilesRegistry;
    }

    // Filter controls card
    if (UITheme::beginCard("RecFilterCard", "Filter & Search Recovered Artifacts",
                           "FORENSIC INVENTORY", UITheme::COLOR_BLUE)) {
        ImGui::Columns(3, nullptr, false);

        UITheme::renderWrappedText("Search Filename / Ext:", UITheme::COLOR_TEXT_MUTED);
        ImGui::SetNextItemWidth(-10);
        ImGui::InputText("##SearchRec", searchFilterBuffer_, sizeof(searchFilterBuffer_));

        ImGui::NextColumn();

        UITheme::renderWrappedText("Recovery Discipline:", UITheme::COLOR_TEXT_MUTED);
        const char* sources[] = { "All Disciplines", "Raw Data Carver Only", "Filesystem Metadata Only" };
        ImGui::SetNextItemWidth(-10);
        ImGui::Combo("##SourceCombo", &selectedSourceFilter_, sources, IM_ARRAYSIZE(sources));

        ImGui::NextColumn();

        UITheme::renderWrappedText("File Category:", UITheme::COLOR_TEXT_MUTED);
        const char* types[] = { "All Categories", "PDF Documents", "Office (DOCX/XLSX/OLE)", "Images (JPEG/PNG/GIF)", "Audio/Video Media" };
        ImGui::SetNextItemWidth(-10);
        ImGui::Combo("##TypeCombo", &selectedTypeFilter_, types, IM_ARRAYSIZE(types));

        ImGui::Columns(1);
    }
    UITheme::endCard();

    // Filter items
    std::string searchLower = searchFilterBuffer_;
    std::transform(searchLower.begin(), searchLower.end(), searchLower.begin(), ::tolower);

    std::vector<UnifiedRecoveredFile> filtered;
    for (const auto& f : filesCopy) {
        // Search filter
        if (!searchLower.empty()) {
            std::string fnLower = f.filename;
            std::transform(fnLower.begin(), fnLower.end(), fnLower.begin(), ::tolower);
            if (fnLower.find(searchLower) == std::string::npos &&
                f.fileType.find(searchLower) == std::string::npos) {
                continue;
            }
        }

        // Source filter
        if (selectedSourceFilter_ == 1 && f.source != "CARVER") continue;
        if (selectedSourceFilter_ == 2 && f.source != "FILESYSTEM") continue;

        // Type filter
        if (selectedTypeFilter_ == 1) { // PDF
            if (f.fileType.find("PDF") == std::string::npos && f.extension != "pdf") continue;
        } else if (selectedTypeFilter_ == 2) { // Office
            if (f.fileType.find("DOC") == std::string::npos &&
                f.fileType.find("XLS") == std::string::npos &&
                f.fileType.find("PPT") == std::string::npos &&
                f.fileType.find("ZIP") == std::string::npos) continue;
        } else if (selectedTypeFilter_ == 3) { // Images
            if (f.fileType.find("JPEG") == std::string::npos &&
                f.fileType.find("PNG") == std::string::npos &&
                f.fileType.find("GIF") == std::string::npos) continue;
        } else if (selectedTypeFilter_ == 4) { // Media
            if (f.fileType.find("MP3") == std::string::npos &&
                f.fileType.find("MP4") == std::string::npos) continue;
        }

        filtered.push_back(f);
    }

    // Summary & Export Toolbar
    ImGui::TextColored(UITheme::COLOR_TEXT_PRIMARY, "Showing %zu of %zu recovered artifacts",
                       filtered.size(), filesCopy.size());

    ImGui::SameLine(ImGui::GetWindowWidth() - 320.0f);
    if (UITheme::renderSecondaryButton("Export Manifest (.csv)...", ImVec2(180, 32))) {
        std::string savePath = FileDialog::saveFile("Export Artifact Manifest", "artifact_manifest.csv", "CSV Files (*.csv)", "*.csv;*.*");
        if (!savePath.empty()) {
            std::ofstream out(savePath);
            if (out.is_open()) {
                out << "ID,Source,Filename,Type,SizeBytes,ByteOffset,Confidence,ConfidenceLevel,SHA256,Timestamp\n";
                for (const auto& item : filtered) {
                    out << item.id << "," << item.source << ",\"" << item.filename << "\","
                        << item.fileType << "," << item.sizeBytes << "," << item.byteOffset << ","
                        << item.confidence << "," << item.confidenceLevel << "," << item.sha256 << ",\""
                        << item.timestamp << "\"\n";
                }
                ctx.postNotification(Notification::Type::SUCCESS, "Manifest Exported", "Saved CSV manifest to: " + savePath);
            }
        }
    }

    ImGui::SameLine();
    if (UITheme::renderGhostButton("Clear Registry", ImVec2(110, 32))) {
        std::lock_guard<std::mutex> lock(ctx.registryMutex);
        ctx.recoveredFilesRegistry.clear();
    }

    ImGui::Spacing();

    // Table
    if (filtered.empty()) {
        if (filesCopy.empty()) {
            if (UITheme::beginCard("NoRecCard", nullptr, nullptr, UITheme::COLOR_ORANGE, 100.0f)) {
                ImGui::TextColored(UITheme::COLOR_TEXT_MUTED,
                    "No artifacts currently registered. Execute File Carving or Filesystem Recovery to extract and view recovered files here.");
            }
            UITheme::endCard();
        } else {
            ImGui::TextColored(UITheme::COLOR_YELLOW, "No recovered artifacts matched the active filters.");
        }
        return;
    }

    int tableFlags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                     ImGuiTableFlags_Resizable | ImGuiTableFlags_Sortable;
    if (filtered.size() > 25) tableFlags |= ImGuiTableFlags_ScrollY;
    float tableH = (filtered.size() > 25) ? 500.0f : 0.0f;

    if (ImGui::BeginTable("RecoveredFilesTable", 8, tableFlags, ImVec2(0, tableH))) {
        ImGui::TableSetupColumn("ID", ImGuiTableColumnFlags_WidthFixed, 45.0f);
        ImGui::TableSetupColumn("Discipline", ImGuiTableColumnFlags_WidthFixed, 100.0f);
        ImGui::TableSetupColumn("File Name", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 90.0f);
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 90.0f);
        ImGui::TableSetupColumn("Offset (Hex)", ImGuiTableColumnFlags_WidthFixed, 110.0f);
        ImGui::TableSetupColumn("Confidence", ImGuiTableColumnFlags_WidthFixed, 130.0f);
        ImGui::TableSetupColumn("SHA-256 Hash", ImGuiTableColumnFlags_WidthFixed, 180.0f);
        ImGui::TableHeadersRow();

        for (const auto& item : filtered) {
            ImGui::TableNextRow();

            // ID
            ImGui::TableSetColumnIndex(0);
            ImGui::Text("%llu", static_cast<unsigned long long>(item.id));

            // Discipline
            ImGui::TableSetColumnIndex(1);
            if (item.source == "CARVER") {
                UITheme::renderBadge("CARVED", UITheme::COLOR_ORANGE);
            } else {
                UITheme::renderBadge("FILESYSTEM", UITheme::COLOR_BLUE);
            }

            // Filename
            ImGui::TableSetColumnIndex(2);
            ImGui::Text("%s", item.filename.c_str());

            // Type
            ImGui::TableSetColumnIndex(3);
            ImGui::TextColored(UITheme::COLOR_ORANGE, "%s", item.fileType.c_str());

            // Size
            ImGui::TableSetColumnIndex(4);
            if (item.sizeBytes < 1024) {
                ImGui::Text("%llu B", static_cast<unsigned long long>(item.sizeBytes));
            } else if (item.sizeBytes < 1024 * 1024) {
                ImGui::Text("%.1f KB", item.sizeBytes / 1024.0);
            } else {
                ImGui::Text("%.2f MB", item.sizeBytes / (1024.0 * 1024.0));
            }

            // Offset
            ImGui::TableSetColumnIndex(5);
            if (UITheme::fontMono) ImGui::PushFont(UITheme::fontMono);
            std::stringstream offSs;
            offSs << "0x" << std::hex << std::uppercase << item.byteOffset;
            ImGui::Text("%s", offSs.str().c_str());
            if (UITheme::fontMono) ImGui::PopFont();

            // Confidence
            ImGui::TableSetColumnIndex(6);
            std::stringstream confSs;
            confSs << std::fixed << std::setprecision(0) << item.confidence << "% (" << item.confidenceLevel << ")";
            ImVec4 confCol = UITheme::COLOR_GREEN;
            if (item.confidenceLevel == "MEDIUM") confCol = UITheme::COLOR_YELLOW;
            else if (item.confidenceLevel == "LOW" || item.confidenceLevel == "UNCERTAIN") confCol = UITheme::COLOR_RED;
            UITheme::renderBadge(confSs.str().c_str(), confCol);

            // Hash
            ImGui::TableSetColumnIndex(7);
            if (UITheme::fontMono) ImGui::PushFont(UITheme::fontMono);
            if (!item.sha256.empty()) {
                std::string shortHash = (item.sha256.size() > 16) ? item.sha256.substr(0, 16) + "..." : item.sha256;
                ImGui::Text("%s", shortHash.c_str());
            } else {
                ImGui::TextDisabled("—");
            }
            if (UITheme::fontMono) ImGui::PopFont();
        }

        ImGui::EndTable();
    }
}

} // namespace forensivault::gui
