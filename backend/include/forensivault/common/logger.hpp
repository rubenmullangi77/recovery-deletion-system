#pragma once

#include <iostream>
#include <string>
#include <sstream>
#include <mutex>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <io.h>
#define isatty _isatty
#define fileno _fileno
#else
#include <unistd.h>
#endif

namespace forensivault {

class Logger {
public:
    static Logger& getInstance() {
        static Logger instance;
        return instance;
    }

    void print(const std::string& text) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::cout << text << std::flush;
    }

    void println(const std::string& text = "") {
        std::lock_guard<std::mutex> lock(mutex_);
        if (text.empty()) {
            std::cout << '\n';
            return;
        }

        if (!stdoutIsAtty_) {
            std::cout << text << '\n';
            return;
        }

        std::cout << colorizeTags(text) << '\n';
    }

    void printlnErr(const std::string& text = "") {
        std::lock_guard<std::mutex> lock(mutex_);
        if (text.empty()) {
            std::cerr << '\n';
            return;
        }

        if (!stderrIsAtty_) {
            std::cerr << text << '\n';
            return;
        }

        // Error printing is bold RED per requirement
        std::cerr << "\033[1;31m" << text << "\033[0m\n";
    }

private:
    Logger() {
#if defined(_WIN32)
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut != INVALID_HANDLE_VALUE && hOut != NULL) {
            DWORD dwMode = 0;
            if (GetConsoleMode(hOut, &dwMode)) {
                dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
                SetConsoleMode(hOut, dwMode);
            }
        }
        HANDLE hErr = GetStdHandle(STD_ERROR_HANDLE);
        if (hErr != INVALID_HANDLE_VALUE && hErr != NULL) {
            DWORD dwMode = 0;
            if (GetConsoleMode(hErr, &dwMode)) {
                dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
                SetConsoleMode(hErr, dwMode);
            }
        }
        stdoutIsAtty_ = (_isatty(_fileno(stdout)) != 0);
        stderrIsAtty_ = (_isatty(_fileno(stderr)) != 0);
#else
        stdoutIsAtty_ = (isatty(fileno(stdout)) != 0);
        stderrIsAtty_ = (isatty(fileno(stderr)) != 0);
#endif
    }

    std::string colorizeTags(const std::string& str) const {
        // If line is a visual border like "=====" or "-----", colorize in cyan
        if (str.rfind("=====", 0) == 0 || str.rfind("-----", 0) == 0) {
            return "\033[1;36m" + str + "\033[0m";
        }

        // Color table for status prefixes:
        static const std::pair<const char*, const char*> kTagColors[] = {
            { "[SUCCESS]", "\033[1;32m" }, // Green
            { "[+]",       "\033[1;32m" },
            { "[OK]",      "\033[1;32m" },
            { "[       OK ]", "\033[1;32m" },
            { "[PASSED 100%]", "\033[1;32m" },
            { "[FZF Selected]:", "\033[1;32m" },
            { "[ELEVATED - ROOT / ADMINISTRATOR]", "\033[1;32m" },

            { "[ERROR]",   "\033[1;31m" }, // Red
            { "[FAILED]",  "\033[1;31m" },
            { "[  FAILED  ]", "\033[1;31m" },
            { "[FAILURE]", "\033[1;31m" },
            { "[CRITICAL SAFETY BLOCK]", "\033[1;31m" },
            { "[PROHIBITED - SYSTEM PATH DETECTED]", "\033[1;31m" },
            { "PERMANENT DESTRUCTION WARNING", "\033[1;31m" },

            { "[WARN]",    "\033[1;33m" }, // Yellow
            { "[WARNING]", "\033[1;33m" },
            { "[!]",       "\033[1;33m" },
            { "[PERMISSION NOTICE]", "\033[1;33m" },
            { "[PERMISSION DENIED]", "\033[1;33m" },
            { "[ELEVATION REQUIRED]", "\033[1;33m" },
            { "[STANDARD USER - NOT ELEVATED]", "\033[1;33m" },

            { "[INFO]",    "\033[1;36m" }, // Cyan
            { "[*]",       "\033[1;36m" },
            { "[AUDIT]",   "\033[1;36m" },

            { "[CARVING]",    "\033[1;35m" }, // Magenta
            { "[SANITIZING]", "\033[1;35m" },
            { "[FILESYSTEM]", "\033[1;35m" },
        };

        std::string result = str;
        for (const auto& entry : kTagColors) {
            const std::string tag = entry.first;
            const std::string col = entry.second;
            size_t pos = 0;
            while ((pos = result.find(tag, pos)) != std::string::npos) {
                std::string replacement = col + tag + "\033[0m";
                result.replace(pos, tag.length(), replacement);
                pos += replacement.length();
            }
        }
        return result;
    }

    std::mutex mutex_;
    bool stdoutIsAtty_{false};
    bool stderrIsAtty_{false};
};

// Strictly ONE of each macro (LN versions) as requested
#define FV_PRINTLN(msg)    forensivault::Logger::getInstance().println(msg)
#define FV_PRINTERRLN(msg) forensivault::Logger::getInstance().printlnErr(msg)

} // namespace forensivault
