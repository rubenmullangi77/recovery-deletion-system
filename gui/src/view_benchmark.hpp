#include "async_task.hpp"
#include <string>
#include <atomic>
#include <mutex>

namespace forensivault::gui {

class ViewBenchmark {
public:
    ViewBenchmark();

    void render();

private:
    char payloadBuffer_[1024];

    // Benchmark execution & results
    AsyncTaskRunner benchRunner_;
    std::atomic<bool> hasResult_{false};
    std::mutex resultMutex_;
    std::string sha256Hash_;
    std::string md5Hash_;
    double entropyScore_ = 0.0;
    double throughputMBps_ = 0.0;
};

} // namespace forensivault::gui
