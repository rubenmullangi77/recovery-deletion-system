#include "view_settings_about.hpp"
#include "ui_theme.hpp"
#include "app_context.hpp"
#include <forensivault/common/crypto_hash.hpp>

#include <imgui.h>
#include <iomanip>
#include <sstream>
#include <vector>
#include <chrono>

namespace forensivault::gui {

ViewSettingsAbout::ViewSettingsAbout() {
    testSizeMb_ = 64;
}

void ViewSettingsAbout::render() {
    UITheme::renderCardHeader("SETTINGS, COMPLIANCE & PLATFORM SPECIFICATIONS",
                              "Forensic Standards Accreditation, Cryptographic Benchmarking & Workstation Security");

    renderThemeSettings();
    renderComplianceSpecs();
    renderSecurityContext();
    renderCryptoBenchmark();
    renderAboutPlatform();
}

void ViewSettingsAbout::renderThemeSettings() {
    auto& ctx = AppContext::getInstance();
    bool isDark = UITheme::isDarkTheme();

    if (UITheme::beginCard("SetCard_Theme", "Workstation Theme",
                           isDark ? "DARK" : "LIGHT",
                           isDark ? UITheme::COLOR_BLUE : UITheme::COLOR_ORANGE)) {
        ImGui::TextColored(UITheme::COLOR_TEXT_PRIMARY, "Select your theme");
        ImGui::Spacing();

        int themeChoice = isDark ? 1 : 0;
        if (ImGui::RadioButton("Light", &themeChoice, 0)) {
            if (isDark) ctx.setDarkTheme(false);
        }
        ImGui::Spacing();
        if (ImGui::RadioButton("Dark", &themeChoice, 1)) {
            if (!isDark) ctx.setDarkTheme(true);
        }
    }
    UITheme::endCard();
}

void ViewSettingsAbout::renderComplianceSpecs() {
    if (UITheme::beginCard("SetCard_Compliance", "Forensic Sanitization & Recovery Standards Compliance",
                           "CERTIFIED SPECIFICATION", UITheme::COLOR_GREEN)) {
        ImGui::Columns(3, nullptr, false);

        UITheme::renderWrappedText("NIST SP 800-88 Rev 1", UITheme::COLOR_ORANGE);
        UITheme::renderWrappedText("Media Sanitization Guidelines", UITheme::COLOR_TEXT_PRIMARY);
        ImGui::Spacing();
        UITheme::renderWrappedText("Implements 'Clear' single-pass zero overwrite with lead, median, and tail sampling verification.", UITheme::COLOR_TEXT_MUTED);

        ImGui::NextColumn();

        UITheme::renderWrappedText("DoD 5220.22-M", UITheme::COLOR_ORANGE);
        UITheme::renderWrappedText("National Industrial Security", UITheme::COLOR_TEXT_PRIMARY);
        ImGui::Spacing();
        UITheme::renderWrappedText("3-Pass overwrite standard (0x00, 0xFF, Cryptographic PRNG) for non-volatile magnetic storage.", UITheme::COLOR_TEXT_MUTED);

        ImGui::NextColumn();

        UITheme::renderWrappedText("ISO/IEC 27040", UITheme::COLOR_BLUE);
        UITheme::renderWrappedText("Storage Security Architecture", UITheme::COLOR_TEXT_PRIMARY);
        ImGui::Spacing();
        UITheme::renderWrappedText("Enforces immutable read-only evidence access and SHA-256 chained tamper-evident audit logging.", UITheme::COLOR_TEXT_MUTED);

        ImGui::Columns(1);
    }
    UITheme::endCard();
}

void ViewSettingsAbout::renderSecurityContext() {
    auto& ctx = AppContext::getInstance();

    if (UITheme::beginCard("SetCard_Security", "Operating System Security & Privileges",
                           ctx.isElevated ? "ELEVATED" : "STANDARD",
                           ctx.isElevated ? UITheme::COLOR_GREEN : UITheme::COLOR_YELLOW)) {
        ImGui::Columns(2, nullptr, false);

        UITheme::renderWrappedText("Host Operating System:", UITheme::COLOR_TEXT_MUTED);
        UITheme::renderWrappedText(ctx.platformName.c_str(), UITheme::COLOR_TEXT_PRIMARY);
        ImGui::Spacing();
        UITheme::renderWrappedText("Execution Privilege Level:", UITheme::COLOR_TEXT_MUTED);
        const char* privDesc = ctx.isElevated ? "Administrator / Elevated (Full Raw I/O)"
                                              : "Standard User (Restricted to Virtual Images & Files)";
        UITheme::renderWrappedText(privDesc, ctx.isElevated ? UITheme::COLOR_GREEN : UITheme::COLOR_YELLOW);

        ImGui::NextColumn();

        if (!ctx.isElevated) {
            UITheme::renderWrappedText("Elevate privileges to enable direct physical drive sanitization and raw disk enumeration.", UITheme::COLOR_YELLOW);
            ImGui::Spacing();
            const char* btnElev = ctx.platformName == "Windows" ? "Request Elevation (UAC)..." : "Request Elevation (Polkit)...";
            if (UITheme::renderPrimaryButton(btnElev, ImVec2(-1, 34))) {
                ctx.requestElevation();
            }
        } else {
            UITheme::renderWrappedText("Full kernel-level raw I/O privileges are active.", UITheme::COLOR_GREEN);
            ImGui::Spacing();
            UITheme::renderWrappedText("Physical drives and partition tables can be inspected directly.", UITheme::COLOR_TEXT_MUTED);
        }

        ImGui::Columns(1);
    }
    UITheme::endCard();
}

void ViewSettingsAbout::renderCryptoBenchmark() {
    if (UITheme::beginCard("SetCard_Benchmark", "Cryptographic Hashing Performance Benchmark",
                           "HARDWARE CSPRNG & HASH ACCELERATION", UITheme::COLOR_ORANGE)) {
        ImGui::TextColored(UITheme::COLOR_TEXT_SECONDARY,
            "Measure hardware memory throughput and cryptographic hashing speeds for evidence acquisition:");
        ImGui::Spacing();

        ImGui::Text("Buffer Test Volume:");
        ImGui::SameLine();
        ImGui::RadioButton("32 MB", &testSizeMb_, 32);
        ImGui::SameLine();
        ImGui::RadioButton("64 MB", &testSizeMb_, 64);
        ImGui::SameLine();
        ImGui::RadioButton("128 MB", &testSizeMb_, 128);

        ImGui::SameLine(ImGui::GetWindowWidth() - 250.0f);

        bool canRun = !benchRunner_.isRunning();
        if (!canRun) ImGui::BeginDisabled();

        if (UITheme::renderSecondaryButton("Run Hashing Benchmark", ImVec2(230, 32))) {
            hasBenchResult_ = false;
            int sizeMb = testSizeMb_;
            benchRunner_.run([this, sizeMb]() {
                const size_t CHUNK = 1024 * 1024;
                std::vector<uint8_t> block(CHUNK, 0x5A);

                // SHA-256 Benchmark
                auto startSha = std::chrono::high_resolution_clock::now();
                forensivault::CryptoHash::Sha256Context shaCtx;
                for (int i = 0; i < sizeMb; ++i) {
                    shaCtx.update(block.data(), block.size());
                }
                shaCtx.finalize();
                auto endSha = std::chrono::high_resolution_clock::now();
                double shaSec = std::chrono::duration<double>(endSha - startSha).count();
                sha256TimeMs_ = shaSec * 1000.0;
                sha256SpeedMBps_ = (shaSec > 0.0) ? (static_cast<double>(sizeMb) / shaSec) : 0.0;

                // MD5 Benchmark
                auto startMd5 = std::chrono::high_resolution_clock::now();
                forensivault::CryptoHash::Md5Context md5Ctx;
                for (int i = 0; i < sizeMb; ++i) {
                    md5Ctx.update(block.data(), block.size());
                }
                md5Ctx.finalize();
                auto endMd5 = std::chrono::high_resolution_clock::now();
                double md5Sec = std::chrono::duration<double>(endMd5 - startMd5).count();
                md5TimeMs_ = md5Sec * 1000.0;
                md5SpeedMBps_ = (md5Sec > 0.0) ? (static_cast<double>(sizeMb) / md5Sec) : 0.0;

                hasBenchResult_ = true;
            });
        }

        if (!canRun) ImGui::EndDisabled();

        if (benchRunner_.isRunning()) {
            ImGui::Spacing();
            UITheme::renderProgressBar(-1.0f * (float)ImGui::GetTime(), "Benchmarking CPU cryptographic pipelines...", "Testing SHA-256 and MD5 throughput...");
        }

        if (hasBenchResult_) {
            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();

            ImGui::Columns(2, nullptr, false);

            // SHA-256 Card
            std::stringstream shaSpeed;
            shaSpeed << std::fixed << std::setprecision(1) << sha256SpeedMBps_ << " MB/s";
            std::stringstream shaTime;
            shaTime << std::fixed << std::setprecision(2) << sha256TimeMs_ << " ms (" << testSizeMb_ << " MB payload)";
            UITheme::renderMetricTile("SHA-256 Throughput", shaSpeed.str().c_str(), shaTime.str().c_str(), UITheme::COLOR_GREEN, -1);

            ImGui::NextColumn();

            // MD5 Card
            std::stringstream md5Speed;
            md5Speed << std::fixed << std::setprecision(1) << md5SpeedMBps_ << " MB/s";
            std::stringstream md5Time;
            md5Time << std::fixed << std::setprecision(2) << md5TimeMs_ << " ms (" << testSizeMb_ << " MB payload)";
            UITheme::renderMetricTile("MD5 Throughput", md5Speed.str().c_str(), md5Time.str().c_str(), UITheme::COLOR_BLUE, -1);

            ImGui::Columns(1);
        }
    }
    UITheme::endCard();
}

void ViewSettingsAbout::renderAboutPlatform() {
    if (UITheme::beginCard("SetCard_About", "About ForensiVault Forensic Station", "v1.0.0 RELEASE", UITheme::COLOR_ORANGE)) {
        ImGui::TextColored(UITheme::COLOR_ORANGE, "ForensiVault Desktop Engine");
        UITheme::renderWrappedText("Unified Forensic Recovery, File Carving & Certified Media Sanitization Platform", UITheme::COLOR_TEXT_SECONDARY);
        ImGui::Spacing();

        ImGui::Text("Core Architecture:   C++17 Standalone Engine (`forensivault_core`)");
        ImGui::Text("Interface Subsystem: Dear ImGui v1.91.8 + GLFW 3.3.9 (OpenGL 3.3)");
        ImGui::Text("Cryptographic Engine: OpenSSL / Platform Hardware CSPRNG");
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        UITheme::renderWrappedText(
            "Forensic Immutability Notice: Evidence sources are accessed in read-only mode. Destructive sanitization requires explicit confirmation and cannot be undone.",
            UITheme::COLOR_TEXT_MUTED);
    }
    UITheme::endCard();
}

} // namespace forensivault::gui
