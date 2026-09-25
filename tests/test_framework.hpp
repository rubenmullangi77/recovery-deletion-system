#pragma once

#include "forensivault/common/logger.hpp"
#include <string>
#include <vector>
#include <functional>
#include <chrono>
#include <cmath>
#include <sstream>

namespace forensivault::testing {

struct TestFailure {
    std::string condition;
    std::string message;
    std::string file;
    int line;
};

class TestCase {
public:
    TestCase(std::string suiteName, std::string testName, std::function<void()> func)
        : suiteName_(std::move(suiteName)), testName_(std::move(testName)), func_(std::move(func)) {}

    void run() {
        failures_.clear();
        try {
            func_();
        } catch (const std::exception& e) {
            recordFailure("Exception", e.what(), __FILE__, __LINE__);
        } catch (...) {
            recordFailure("Unknown", "Unhandled non-std exception", __FILE__, __LINE__);
        }
    }

    void recordFailure(std::string condition, std::string message, std::string file, int line) {
        failures_.push_back({std::move(condition), std::move(message), std::move(file), line});
    }

    [[nodiscard]] const std::string& suiteName() const { return suiteName_; }
    [[nodiscard]] const std::string& testName() const { return testName_; }
    [[nodiscard]] bool passed() const { return failures_.empty(); }
    [[nodiscard]] const std::vector<TestFailure>& failures() const { return failures_; }

private:
    std::string suiteName_;
    std::string testName_;
    std::function<void()> func_;
    std::vector<TestFailure> failures_;
};

class TestRegistry {
public:
    static TestRegistry& getInstance() {
        static TestRegistry instance;
        return instance;
    }

    void registerTest(const std::string& suite, const std::string& name, std::function<void()> func) {
        tests_.emplace_back(suite, name, std::move(func));
    }

    void setCurrentTest(TestCase* test) {
        currentTest_ = test;
    }

    TestCase* currentTest() {
        return currentTest_;
    }

    int runAll() {
        int passed = 0;
        int failed = 0;

        FV_PRINTLN("\n============================================================");
        FV_PRINTLN("        ForensiVault Automated Forensic Test Suite          ");
        FV_PRINTLN("============================================================\n");

        auto start = std::chrono::high_resolution_clock::now();

        for (auto& test : tests_) {
            setCurrentTest(&test);
            FV_PRINTLN("[ RUN      ] " + test.suiteName() + "." + test.testName());
            
            test.run();

            if (test.passed()) {
                FV_PRINTLN("[       OK ] " + test.suiteName() + "." + test.testName());
                passed++;
            } else {
                FV_PRINTERRLN("[  FAILED  ] " + test.suiteName() + "." + test.testName());
                for (const auto& f : test.failures()) {
                    std::string failMsg = "  --> " + f.file + ":" + std::to_string(f.line) + " | " + f.condition;
                    if (!f.message.empty()) {
                        failMsg += " (" + f.message + ")";
                    }
                    FV_PRINTERRLN(failMsg);
                }
                failed++;
            }
        }

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::high_resolution_clock::now() - start).count();

        FV_PRINTLN("\n============================================================");
        std::string summary = " Test Summary: " + std::to_string(passed + failed) + " total | " +
                              std::to_string(passed) + " passed | " +
                              std::to_string(failed) + " failed | " +
                              std::to_string(elapsed) + " ms";
        if (failed == 0) {
            FV_PRINTLN(summary);
        } else {
            FV_PRINTERRLN(summary);
        }
        FV_PRINTLN("============================================================\n");

        return failed == 0 ? 0 : 1;
    }

private:
    TestRegistry() = default;
    std::vector<TestCase> tests_;
    TestCase* currentTest_{nullptr};
};

struct TestAutoRegistrar {
    TestAutoRegistrar(const std::string& suite, const std::string& name, std::function<void()> func) {
        TestRegistry::getInstance().registerTest(suite, name, std::move(func));
    }
};

} // namespace forensivault::testing

#define FV_TEST(suite, name) \
    static void _fv_test_##suite##_##name(); \
    static const ::forensivault::testing::TestAutoRegistrar _fv_reg_##suite##_##name( \
        #suite, #name, &_fv_test_##suite##_##name); \
    static void _fv_test_##suite##_##name()

#define ASSERT_TRUE(expr) \
    do { \
        if (!(expr)) { \
            auto* curr = ::forensivault::testing::TestRegistry::getInstance().currentTest(); \
            if (curr) curr->recordFailure(#expr, "Expected true, got false", __FILE__, __LINE__); \
            return; \
        } \
    } while (0)

#define ASSERT_FALSE(expr) \
    do { \
        if (expr) { \
            auto* curr = ::forensivault::testing::TestRegistry::getInstance().currentTest(); \
            if (curr) curr->recordFailure(#expr, "Expected false, got true", __FILE__, __LINE__); \
            return; \
        } \
    } while (0)

#define ASSERT_EQ(val1, val2) \
    do { \
        if ((val1) != (val2)) { \
            std::ostringstream ss; \
            ss << "Expected " << (val1) << " == " << (val2); \
            auto* curr = ::forensivault::testing::TestRegistry::getInstance().currentTest(); \
            if (curr) curr->recordFailure(#val1 " == " #val2, ss.str(), __FILE__, __LINE__); \
            return; \
        } \
    } while (0)

#define ASSERT_NE(val1, val2) \
    do { \
        if ((val1) == (val2)) { \
            std::ostringstream ss; \
            ss << "Expected " << (val1) << " != " << (val2); \
            auto* curr = ::forensivault::testing::TestRegistry::getInstance().currentTest(); \
            if (curr) curr->recordFailure(#val1 " != " #val2, ss.str(), __FILE__, __LINE__); \
            return; \
        } \
    } while (0)

#define ASSERT_NEAR(val1, val2, epsilon) \
    do { \
        if (std::abs((val1) - (val2)) > (epsilon)) { \
            std::ostringstream ss; \
            ss << "Expected |" << (val1) << " - " << (val2) << "| <= " << (epsilon); \
            auto* curr = ::forensivault::testing::TestRegistry::getInstance().currentTest(); \
            if (curr) curr->recordFailure(#val1 " near " #val2, ss.str(), __FILE__, __LINE__); \
            return; \
        } \
    } while (0)
