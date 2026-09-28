#pragma once

#include <string>

namespace forensivault::gui {

class ViewBenchmark {
public:
    ViewBenchmark();

    void render();

private:
    char payloadBuffer_[1024];

    // Benchmark results
    bool hasResult_ = false;
    std::string sha256Hash_;
    std::string md5Hash_;
    double entropyScore_ = 0.0;
    double throughputMBps_ = 0.0;
};

} // namespace forensivault::gui
