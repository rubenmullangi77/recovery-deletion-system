#include "view_benchmark.hpp"
#include "ui_theme.hpp"
#include "app_context.hpp"

#include <forensivault/common/crypto_hash.hpp>

#include <imgui.h>
#include <cstring>
#include <chrono>
#include <vector>

namespace forensivault::gui {

ViewBenchmark::ViewBenchmark() {
    std::strncpy(payloadBuffer_, "ForensiVault Forensic Integrity Test Payload 2026", sizeof(payloadBuffer_) - 1);
}

void ViewBenchmark::render() {
    UITheme::renderCardHeader("MODULE 7: CRYPTOGRAPHIC HASHING & ENTROPY BENCHMARK",
                              "Hardware Cryptographic Acceleration, Shannon Entropy & Throughput Micro-Benchmarking");

    ImGui::Text("Test String / Payload:");
    ImGui::PushItemWidth(-1);
    ImGui::InputText("##BenchmarkPayload", payloadBuffer_, sizeof(payloadBuffer_));
    ImGui::PopItemWidth();

    ImGui::Spacing();

    if (UITheme::renderPrimaryButton("Run Cryptographic Integrity Benchmark", ImVec2(340, 38))) {
        std::string payload = payloadBuffer_;
        sha256Hash_ = forensivault::CryptoHash::sha256(payload);
        md5Hash_ = forensivault::CryptoHash::md5(payload);
        entropyScore_ = forensivault::CryptoHash::calculateEntropy(
            reinterpret_cast<const uint8_t*>(payload.data()), payload.size());

        // Micro-benchmark 32 MB streaming throughput
        std::vector<uint8_t> benchBlock(1024 * 1024, 0xA5); // 1 MB block
        auto start = std::chrono::high_resolution_clock::now();
        forensivault::CryptoHash::Sha256Context ctx;
        for (int i = 0; i < 32; ++i) {
            ctx.update(benchBlock.data(), benchBlock.size());
        }
        ctx.finalize();
        auto end = std::chrono::high_resolution_clock::now();
        double elapsedSec = std::chrono::duration<double>(end - start).count();
        throughputMBps_ = (elapsedSec > 0.0) ? (32.0 / elapsedSec) : 0.0;

        hasResult_ = true;
    }

    if (hasResult_) {
        ImGui::Spacing();
        ImGui::PushStyleColor(ImGuiCol_ChildBg, UITheme::COLOR_BG_PANEL);
        ImGui::BeginChild("BenchResultsCard", ImVec2(0, 200), true);

        ImGui::TextColored(UITheme::COLOR_GREEN, "[CRYPTOGRAPHIC CORE OPERATIONAL]");
        ImGui::Separator();
        ImGui::Spacing();

        ImGui::Text("SHA-256: ");
        ImGui::SameLine();
        ImGui::TextColored(UITheme::COLOR_CYAN, "%s", sha256Hash_.c_str());

        ImGui::Spacing();
        ImGui::Text("MD5:     ");
        ImGui::SameLine();
        ImGui::TextColored(UITheme::COLOR_CYAN, "%s", md5Hash_.c_str());

        ImGui::Spacing();
        ImGui::Text("Shannon Entropy: %.4f bits/byte (Theoretical Max: 8.0 bits/byte)", entropyScore_);

        ImGui::Spacing();
        ImGui::Text("Streaming SHA-256 Throughput: %.2f MB/s", throughputMBps_);

        ImGui::EndChild();
        ImGui::PopStyleColor();
    }
}

} // namespace forensivault::gui
