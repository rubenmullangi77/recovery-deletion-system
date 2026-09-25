#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include "forensivault/common/logger.hpp"
#include <string>
#include <vector>
#include <algorithm>

std::wstring toWide(const std::string& str) {
    if (str.empty()) return L"";
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

std::string toUtf8(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

std::string getErrorMessage(DWORD code) {
    LPWSTR msgBuf = nullptr;
    DWORD size = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&msgBuf, 0, NULL
    );
    std::string result = "";
    if (size > 0 && msgBuf != nullptr) {
        result = toUtf8(msgBuf);
        while (!result.empty() && (result.back() == '\r' || result.back() == '\n' || result.back() == ' ')) {
            result.pop_back();
        }
    } else {
        result = "Windows System Error Code " + std::to_string(code);
    }
    if (msgBuf) {
        LocalFree(msgBuf);
    }
    return result;
}

bool isProcessElevated() {
    BOOL fIsElevated = FALSE;
    HANDLE hToken = NULL;
    TOKEN_ELEVATION elevation;
    DWORD dwSize;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
            fIsElevated = elevation.TokenIsElevated;
        }
    }
    if (hToken) {
        CloseHandle(hToken);
    }
    return fIsElevated != 0;
}

int main(int argc, char* argv[]) {
    // 1. Diagnostic token check flag
    if (argc >= 2 && (std::string(argv[1]) == "--check-elevation" || std::string(argv[1]) == "-c")) {
        bool elevated = isProcessElevated();
        char exePath[MAX_PATH] = { 0 };
        GetModuleFileNameA(NULL, exePath, MAX_PATH);
        char currentDir[MAX_PATH] = { 0 };
        GetCurrentDirectoryA(MAX_PATH, currentDir);

        std::ostringstream ss;
        ss << "{"
           << "\"pid\":" << GetCurrentProcessId() << ","
           << "\"is_elevated\":" << (elevated ? "true" : "false") << ","
           << "\"executable\":\"" << exePath << "\","
           << "\"working_directory\":\"" << currentDir << "\""
           << "}";
        FV_PRINTLN(ss.str());
        return elevated ? 0 : 1;
    }

    if (argc < 3) {
        FV_PRINTLN("Usage: forensivault_elevate <target_exe_or_bat> <working_dir> [params...]");
        FV_PRINTLN("       forensivault_elevate --check-elevation");
        return 1;
    }

    std::string targetExe = argv[1];
    std::string workDir = argv[2];

    // Build parameter string
    std::string params = "";
    for (int i = 3; i < argc; ++i) {
        if (!params.empty()) params += " ";
        std::string p = argv[i];
        if (p.find(' ') != std::string::npos && p.front() != '\"') {
            params += "\"" + p + "\"";
        } else {
            params += p;
        }
    }

    std::wstring wTarget;
    std::wstring wDir = toWide(workDir);
    std::wstring wParams;

    // Check if target is a batch script or executable
    std::string lowerTarget = targetExe;
    std::transform(lowerTarget.begin(), lowerTarget.end(), lowerTarget.begin(), ::tolower);
    bool isBat = (lowerTarget.size() >= 4 && lowerTarget.substr(lowerTarget.size() - 4) == ".bat") ||
                 (lowerTarget.size() >= 4 && lowerTarget.substr(lowerTarget.size() - 4) == ".cmd");

    if (isBat) {
        char comspec[MAX_PATH] = { 0 };
        GetEnvironmentVariableA("COMSPEC", comspec, MAX_PATH);
        if (comspec[0] == '\0') {
            strcpy_s(comspec, "C:\\Windows\\System32\\cmd.exe");
        }
        wTarget = toWide(std::string(comspec));
        std::string fullBatParams = "/c \"\"" + targetExe + "\"";
        if (!params.empty()) {
            fullBatParams += " " + params;
        }
        fullBatParams += "\"";
        wParams = toWide(fullBatParams);
    } else {
        wTarget = toWide(targetExe);
        wParams = toWide(params);
    }

    FV_PRINTLN("[ELEVATION LAUNCH]");
    FV_PRINTLN("target=" + toUtf8(wTarget));
    FV_PRINTLN("working_directory=" + workDir);
    FV_PRINTLN("parameters=" + toUtf8(wParams));
    FV_PRINTLN("verb=runas");

    if (wTarget.find(L'\\') != std::wstring::npos) {
        DWORD attrs = GetFileAttributesW(wTarget.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES) {
            FV_PRINTLN("[ELEVATION ERROR]");
            FV_PRINTLN("stage=TargetCheck");
            FV_PRINTLN("error_code=2");
            FV_PRINTLN("message=Target executable not found: " + toUtf8(wTarget));
            FV_PRINTLN("STATUS:LAUNCH_FAILED");
            FV_PRINTLN("CODE:2");
            return 2;
        }
    }

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.hwnd = GetForegroundWindow();
    sei.lpVerb = L"runas";
    sei.lpFile = wTarget.c_str();
    sei.lpParameters = wParams.empty() ? NULL : wParams.c_str();
    sei.lpDirectory = wDir.empty() ? NULL : wDir.c_str();
    sei.nShow = SW_SHOWNORMAL;

    BOOL ok = ShellExecuteExW(&sei);
    if (!ok) {
        DWORD err = GetLastError();
        std::string errStr = getErrorMessage(err);
        if (err == ERROR_CANCELLED) { // 1223
            FV_PRINTLN("[ELEVATION CANCELLED]");
            FV_PRINTLN("user_cancelled=true");
            FV_PRINTLN("STATUS:CANCELLED");
            FV_PRINTLN("CODE:1223");
            return 1223;
        } else {
            FV_PRINTLN("[ELEVATION ERROR]");
            FV_PRINTLN("stage=ShellExecute");
            FV_PRINTLN("error_code=" + std::to_string(err));
            FV_PRINTLN("message=" + errStr);
            FV_PRINTLN("STATUS:LAUNCH_FAILED");
            FV_PRINTLN("CODE:" + std::to_string(err));
            return (int)err;
        }
    }

    DWORD pid = 0;
    if (sei.hProcess) {
        pid = GetProcessId(sei.hProcess);
        CloseHandle(sei.hProcess);
    }

    FV_PRINTLN("[ELEVATION SUCCESS]");
    FV_PRINTLN("new_pid=" + std::to_string(pid));
    FV_PRINTLN("is_elevated=true");
    FV_PRINTLN("STATUS:SUCCESS");
    FV_PRINTLN("PID:" + std::to_string(pid));
    return 0;
}
