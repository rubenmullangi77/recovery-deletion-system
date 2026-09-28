#pragma once

#include <thread>
#include <atomic>
#include <mutex>
#include <string>
#include <functional>
#include <memory>

namespace forensivault::gui {

class AsyncTaskRunner {
public:
    AsyncTaskRunner() : isRunning_(false), cancelRequested_(false), progressFraction_(0.0f) {}

    ~AsyncTaskRunner() {
        wait();
    }

    // Non-copyable
    AsyncTaskRunner(const AsyncTaskRunner&) = delete;
    AsyncTaskRunner& operator=(const AsyncTaskRunner&) = delete;

    template <typename Func>
    bool run(Func&& taskFunc) {
        if (isRunning_.load()) {
            return false;
        }

        wait();

        isRunning_.store(true);
        cancelRequested_.store(false);
        progressFraction_.store(0.0f);

        {
            std::lock_guard<std::mutex> lock(mutex_);
            statusText_ = "Starting...";
            subStatusText_ = "";
            errorMessage_ = "";
        }

        workerThread_ = std::thread([this, f = std::forward<Func>(taskFunc)]() mutable {
            try {
                f();
            } catch (const std::exception& e) {
                std::lock_guard<std::mutex> lock(mutex_);
                errorMessage_ = e.what();
            } catch (...) {
                std::lock_guard<std::mutex> lock(mutex_);
                errorMessage_ = "Unknown catastrophic error during task execution.";
            }
            isRunning_.store(false);
        });

        return true;
    }

    void requestCancel() {
        cancelRequested_.store(true);
    }

    bool isCancelRequested() const {
        return cancelRequested_.load();
    }

    bool isRunning() const {
        return isRunning_.load();
    }

    void setProgress(float fraction, const std::string& status = "", const std::string& subStatus = "") {
        progressFraction_.store(fraction);
        if (!status.empty() || !subStatus.empty()) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!status.empty()) statusText_ = status;
            if (!subStatus.empty()) subStatusText_ = subStatus;
        }
    }

    float getProgress() const {
        return progressFraction_.load();
    }

    std::string getStatusText() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return statusText_;
    }

    std::string getSubStatusText() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return subStatusText_;
    }

    std::string getErrorMessage() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return errorMessage_;
    }

    void wait() {
        if (workerThread_.joinable()) {
            workerThread_.join();
        }
    }

private:
    std::thread workerThread_;
    std::atomic<bool> isRunning_;
    std::atomic<bool> cancelRequested_;
    std::atomic<float> progressFraction_;
    mutable std::mutex mutex_;
    std::string statusText_;
    std::string subStatusText_;
    std::string errorMessage_;
};

} // namespace forensivault::gui
