#pragma once

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <mutex>
#include <cstdint>

namespace forensivault::gui {

enum class ModuleTab {
    DASHBOARD,
    DRIVE_SANITIZER,
    FILE_ERASER,
    FS_RECOVERY,
    FILE_CARVER,
    OPERATION_PROGRESS,
    RECOVERED_FILES,
    AUDIT_LOG,
    DEVICE_DETECTOR,
    DISK_INSPECT,
    CRYPTO_BENCHMARK,
    SETTINGS_ABOUT
};

struct Notification {
    enum class Type { INFO, SUCCESS, WARNING, FAILURE };
    Type type = Type::INFO;
    std::string title;
    std::string message;
    std::chrono::steady_clock::time_point timestamp;
    float durationSeconds = 6.0f;
};

struct UnifiedRecoveredFile {
    uint64_t id = 0;
    std::string filename;
    std::string fullPath;
    std::string fileType;
    std::string extension;
    uint64_t sizeBytes = 0;
    uint64_t byteOffset = 0;
    double confidence = 0.0;
    std::string confidenceLevel; // "HIGH", "MEDIUM", "LOW", "UNCERTAIN"
    std::string sha256;
    std::string source;          // "CARVER" or "FILESYSTEM"
    std::string timestamp;
};

struct OperationTracker {
    std::mutex mtx;
    bool isRunning = false;
    bool hasFinished = false;
    bool success = false;
    std::string moduleName;
    std::string operationType;
    std::string targetSource;
    std::string destination;
    float progress = 0.0f;
    std::string statusText;
    std::string subStatusText;
    std::chrono::steady_clock::time_point startTime;
    std::chrono::steady_clock::time_point endTime;
    std::vector<std::string> logEvents;

    void reset();
    void start(const std::string& mod, const std::string& type, const std::string& source, const std::string& dest);
    void update(float prg, const std::string& status, const std::string& sub);
    void addLog(const std::string& logLine);
    void finish(bool ok, const std::string& summary);
    float getElapsedSeconds() const;
};

class AppContext {
public:
    static AppContext& getInstance();

    void initialize();

    ModuleTab activeTab = ModuleTab::DASHBOARD;
    bool isElevated = false;
    std::string platformName;

    // Cross-tab transfer fields
    std::string targetDriveForSanitization;
    std::string lastCarvedSource;
    std::string lastRecoverySource;

    // Global Operation Tracker
    OperationTracker currentOperation;

    // Recovered Files Registry
    std::mutex registryMutex;
    std::vector<UnifiedRecoveredFile> recoveredFilesRegistry;

    // Forensic Session Metrics
    uint64_t totalFilesCarved = 0;
    uint64_t totalFilesErased = 0;
    uint64_t totalDrivesSanitized = 0;

    void registerCarvedFile(const std::string& filename, const std::string& fullPath,
                            const std::string& type, uint64_t offset, uint64_t size,
                            double confidence, const std::string& confLevel, const std::string& hash);

    void registerFsFile(const std::string& filename, const std::string& fullPath,
                        uint64_t offset, uint64_t size, const std::string& timestamp);

    // Notification system
    void postNotification(Notification::Type type, const std::string& title, const std::string& message);
    void renderNotifications();

    // Elevation helper
    bool requestElevation(const std::vector<std::string>& extraArgs = {});

private:
    AppContext() = default;
    std::vector<Notification> notifications_;
};

} // namespace forensivault::gui
