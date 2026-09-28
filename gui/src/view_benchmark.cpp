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

    bool canRun = !benchRunner_.isRunning();
    if (!canRun) ImGui::BeginDisabled();

    if (UITheme::renderPrimaryButton("Run Cryptographic Integrity Benchmark", ImVec2(340, 38))) {
        hasResult_.store(false);
        std::string payload = payloadBuffer_;

        benchRunner_.run([this, payload]() {
            std::string sha = forensivault::CryptoHash::sha256(payload);
            std::string md5 = forensivault::CryptoHash::md5(payload);
            double ent = forensivault::CryptoHash::calculateEntropy(
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
            double speed = (elapsedSec > 0.0) ? (32.0 / elapsedSec) : 0.0;

            {
                std::lock_guard<std::mutex> lock(resultMutex_);
                sha256Hash_ = sha;
                md5Hash_ = md5;
                entropyScore_ = ent;
                throughputMBps_ = speed;
            }

            hasResult_.store(true);
        });
    }

    if (!canRun) ImGui::EndDisabled();

    if (benchRunner_.isRunning()) {
        ImGui::Spacing();
        UITheme::renderProgressBar(-1.0f * (float)ImGui::GetTime(), "Executing Cryptographic Benchmark (32 MB Payload)...", "Streaming SHA-256 and Shannon entropy calculations...");
    }

    if (hasResult_.load()) {
        std::string sha, md5;
        double ent = 0.0, speed = 0.0;
        {
            std::lock_guard<std::mutex> lock(resultMutex_);
            sha = sha256Hash_;
            md5 = md5Hash_;
            ent = entropyScore_;
            speed = throughputMBps_;
        }

        ImGui::Spacing();
        if (UITheme::beginCard("BenchResultsCard", "Benchmark Execution Results", "COMPUTED", UITheme::COLOR_GREEN)) {
            UITheme::renderWrappedText("SHA-256 Hash:", UITheme::COLOR_TEXT_MUTED);
            if (UITheme::fontMono) ImGui::PushFont(UITheme::fontMono);
            UITheme::renderWrappedText(sha.c_str(), UITheme::COLOR_ORANGE);
            if (UITheme::fontMono) ImGui::PopFont();

            ImGui::Spacing();
            UITheme::renderWrappedText("MD5 Hash:", UITheme::COLOR_TEXT_MUTED);
            if (UITheme::fontMono) ImGui::PushFont(UITheme::fontMono);
            UITheme::renderWrappedText(md5.c_str(), UITheme::COLOR_BLUE);
            if (UITheme::fontMono) ImGui::PopFont();

            ImGui::Spacing();
            ImGui::Text("Shannon Entropy: %.4f bits/byte (Theoretical Max: 8.0 bits/byte)", ent);

            ImGui::Spacing();
            ImGui::Text("Streaming SHA-256 Throughput: %.2f MB/s", speed);
        }
        UITheme::endCard();
    }
}

} // namespace forensivault::gui
