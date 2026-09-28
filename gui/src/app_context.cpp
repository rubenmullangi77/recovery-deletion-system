#include "app_context.hpp"
#include "ui_theme.hpp"
#include <forensivault/core/platform.hpp>
#include <imgui.h>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace forensivault::gui {

void OperationTracker::reset() {
    std::lock_guard<std::mutex> lock(mtx);
    isRunning = false;
    hasFinished = false;
    success = false;
    moduleName.clear();
    operationType.clear();
    targetSource.clear();
    destination.clear();
    progress = 0.0f;
    statusText = "Idle";
    subStatusText.clear();
    logEvents.clear();
}

void OperationTracker::start(const std::string& mod, const std::string& type,
                             const std::string& source, const std::string& dest) {
    std::lock_guard<std::mutex> lock(mtx);
    isRunning = true;
    hasFinished = false;
    success = false;
    moduleName = mod;
    operationType = type;
    targetSource = source;
    destination = dest;
    progress = 0.0f;
    statusText = "Initializing operation...";
    subStatusText = "Allocating buffers and validating targets...";
    startTime = std::chrono::steady_clock::now();
    logEvents.clear();
    logEvents.push_back("[" + mod + "] Started: " + type + " on target: " + source);
}

void OperationTracker::update(float prg, const std::string& status, const std::string& sub) {
    std::lock_guard<std::mutex> lock(mtx);
    progress = prg;
    if (!status.empty()) statusText = status;
    if (!sub.empty()) subStatusText = sub;
}

void OperationTracker::addLog(const std::string& logLine) {
    std::lock_guard<std::mutex> lock(mtx);
    logEvents.push_back(logLine);
}

void OperationTracker::finish(bool ok, const std::string& summary) {
    std::lock_guard<std::mutex> lock(mtx);
    isRunning = false;
    hasFinished = true;
    success = ok;
    endTime = std::chrono::steady_clock::now();
    progress = ok ? 1.0f : progress;
    statusText = ok ? "Completed successfully." : "Operation terminated with errors.";
    subStatusText = summary;
    logEvents.push_back("[Result] " + statusText + " — " + summary);
}

float OperationTracker::getElapsedSeconds() const {
    auto endPt = isRunning ? std::chrono::steady_clock::now() : endTime;
    return std::chrono::duration<float>(endPt - startTime).count();
}

AppContext& AppContext::getInstance() {
    static AppContext instance;
    return instance;
}

void AppContext::initialize() {
    isElevated = forensivault::core::Platform::isElevated();
#if defined(_WIN32)
    platformName = "Windows x64";
#elif defined(__linux__)
    platformName = "Linux x64";
#else
    platformName = "POSIX Generic";
#endif
    currentOperation.reset();
}

void AppContext::registerCarvedFile(const std::string& filename, const std::string& fullPath,
                                   const std::string& type, uint64_t offset, uint64_t size,
                                   double confidence, const std::string& confLevel, const std::string& hash) {
    std::lock_guard<std::mutex> lock(registryMutex);
    UnifiedRecoveredFile file;
    file.id = recoveredFilesRegistry.size() + 1;
    file.filename = filename;
    file.fullPath = fullPath;
    file.fileType = type;
    file.extension = type;
    file.byteOffset = offset;
    file.sizeBytes = size;
    file.confidence = confidence;
    file.confidenceLevel = confLevel;
    file.sha256 = hash;
    file.source = "CARVER";

    auto t = std::time(nullptr);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&t), "%Y-%m-%d %H:%M:%S UTC");
    file.timestamp = ss.str();

    recoveredFilesRegistry.push_back(file);
    totalFilesCarved++;
}

void AppContext::registerFsFile(const std::string& filename, const std::string& fullPath,
                               uint64_t offset, uint64_t size, const std::string& timestamp) {
    std::lock_guard<std::mutex> lock(registryMutex);
    UnifiedRecoveredFile file;
    file.id = recoveredFilesRegistry.size() + 1;
    file.filename = filename;
    file.fullPath = fullPath;

    // Detect extension
    size_t dot = filename.find_last_of('.');
    if (dot != std::string::npos) {
        file.extension = filename.substr(dot + 1);
        file.fileType = file.extension;
    } else {
        file.fileType = "FILE";
    }

    file.byteOffset = offset;
    file.sizeBytes = size;
    file.confidence = 100.0;
    file.confidenceLevel = "HIGH";
    file.sha256 = "N/A (Filesystem Recovery)";
    file.source = "FILESYSTEM";
    file.timestamp = timestamp.empty() ? "N/A" : timestamp;

    recoveredFilesRegistry.push_back(file);
}

void AppContext::postNotification(Notification::Type type, const std::string& title, const std::string& message) {
    Notification n;
    n.type = type;
    n.title = title;
    n.message = message;
    n.timestamp = std::chrono::steady_clock::now();
    notifications_.push_back(n);
}

void AppContext::renderNotifications() {
    auto now = std::chrono::steady_clock::now();
    for (auto it = notifications_.begin(); it != notifications_.end(); ) {
        float elapsed = std::chrono::duration<float>(now - it->timestamp).count();
        if (elapsed > it->durationSeconds) {
            it = notifications_.erase(it);
            continue;
        }

        ImVec4 col = UITheme::COLOR_BLUE;
        const char* prefix = "[INFO]";
        if (it->type == Notification::Type::SUCCESS) {
            col = UITheme::COLOR_GREEN;
            prefix = "[SUCCESS]";
        } else if (it->type == Notification::Type::WARNING) {
            col = UITheme::COLOR_YELLOW;
            prefix = "[WARNING]";
        } else if (it->type == Notification::Type::FAILURE) {
            col = UITheme::COLOR_RED;
            prefix = "[ERROR]";
        }

        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(col.x, col.y, col.z, 0.12f));
        ImGui::PushStyleColor(ImGuiCol_Border, col);
        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 8.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(14.0f, 8.0f));

        std::string childId = "Notification_" + it->title + std::to_string(elapsed);
        ImGui::BeginChild(childId.c_str(), ImVec2(0, 42), true);
        ImGui::TextColored(col, "%s %s", prefix, it->title.c_str());
        ImGui::SameLine();
        ImGui::TextColored(UITheme::COLOR_TEXT_PRIMARY, "— %s", it->message.c_str());
        ImGui::EndChild();

        ImGui::PopStyleVar(2);
        ImGui::PopStyleColor(2);
        ImGui::Spacing();

        ++it;
    }
}

bool AppContext::requestElevation(const std::vector<std::string>& extraArgs) {
    return forensivault::core::Platform::elevateProcess(extraArgs);
}

} // namespace forensivault::gui
