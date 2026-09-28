#include "file_dialog.hpp"
#include <forensivault/core/platform.hpp>

#include <vector>
#include <iostream>
#include <sstream>
#include <array>
#include <memory>
#include <algorithm>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <commdlg.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <shellapi.h>

namespace {

std::wstring toWide(const std::string& str) {
    if (str.empty()) return L"";
    int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.size()), nullptr, 0);
    std::wstring wstr(sizeNeeded, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.size()), &wstr[0], sizeNeeded);
    return wstr;
}

std::string toNarrow(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), static_cast<int>(wstr.size()), nullptr, 0, nullptr, nullptr);
    std::string str(sizeNeeded, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), static_cast<int>(wstr.size()), &str[0], sizeNeeded, nullptr, nullptr);
    return str;
}

} // anonymous namespace

#else
// Linux / POSIX implementation using zenity or kdialog
namespace {

std::string escapeShellArg(const std::string& arg) {
    std::string escaped = "'";
    for (char c : arg) {
        if (c == '\'') {
            escaped += "'\\''";
        } else {
            escaped += c;
        }
    }
    escaped += "'";
    return escaped;
}

std::string runCommand(const std::string& cmd) {
    std::array<char, 256> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) return "";
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    // Trim newline
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) {
        result.pop_back();
    }
    return result;
}

bool hasCommand(const std::string& cmd) {
    std::string check = "command -v " + escapeShellArg(cmd) + " > /dev/null 2>&1";
    return system(check.c_str()) == 0;
}

} // anonymous namespace
#endif

namespace forensivault::gui {

std::string FileDialog::openFile(const std::string& title,
                                const std::string& filterDesc,
                                const std::string& filterExt) {
    std::string initialDir = forensivault::core::Platform::getUserHomeDirectory();
    if (!initialDir.empty() && initialDir.back() != '/' && initialDir.back() != '\\') {
        initialDir += '/';
    }

#if defined(_WIN32)
    wchar_t filename[MAX_PATH] = { 0 };

    std::wstring wTitle = toWide(title);
    std::wstring wDesc = toWide(filterDesc);
    std::wstring wExt = toWide(filterExt);
    std::wstring wInitDir = toWide(initialDir);

    // Format filter: "Description\0Extension\0\0"
    std::vector<wchar_t> filter;
    for (wchar_t c : wDesc) filter.push_back(c);
    filter.push_back(L'\0');
    for (wchar_t c : wExt) filter.push_back(c);
    filter.push_back(L'\0');
    filter.push_back(L'\0');

    OPENFILENAMEW ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = nullptr;
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = filter.data();
    ofn.nFilterIndex = 1;
    ofn.lpstrTitle = wTitle.c_str();
    ofn.lpstrInitialDir = wInitDir.c_str();
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;

    if (GetOpenFileNameW(&ofn)) {
        return toNarrow(filename);
    }
    return "";
#else
    if (hasCommand("zenity")) {
        std::string cmd = "zenity --file-selection --filename=" + escapeShellArg(initialDir) + " --title=" + escapeShellArg(title) + " 2>/dev/null";
        return runCommand(cmd);
    } else if (hasCommand("kdialog")) {
        std::string cmd = "kdialog --getopenfilename " + escapeShellArg(initialDir) + " --title " + escapeShellArg(title) + " 2>/dev/null";
        return runCommand(cmd);
    }
    return "";
#endif
}

std::string FileDialog::openFolder(const std::string& title) {
    std::string initialDir = forensivault::core::Platform::getUserHomeDirectory();
    if (!initialDir.empty() && initialDir.back() != '/' && initialDir.back() != '\\') {
        initialDir += '/';
    }

#if defined(_WIN32)
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    bool needCoUninit = SUCCEEDED(hr);

    IFileOpenDialog* pFileOpen = nullptr;
    hr = CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_ALL, IID_IFileOpenDialog, reinterpret_cast<void**>(&pFileOpen));
    if (SUCCEEDED(hr)) {
        DWORD dwOptions;
        if (SUCCEEDED(pFileOpen->GetOptions(&dwOptions))) {
            pFileOpen->SetOptions(dwOptions | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM);
        }
        std::wstring wTitle = toWide(title);
        pFileOpen->SetTitle(wTitle.c_str());

        std::wstring wInitDir = toWide(initialDir);
        IShellItem* pFolderItem = nullptr;
        if (SUCCEEDED(SHCreateItemFromParsingName(wInitDir.c_str(), nullptr, IID_PPV_ARGS(&pFolderItem)))) {
            pFileOpen->SetFolder(pFolderItem);
            pFolderItem->Release();
        }

        hr = pFileOpen->Show(nullptr);
        if (SUCCEEDED(hr)) {
            IShellItem* pItem = nullptr;
            hr = pFileOpen->GetResult(&pItem);
            if (SUCCEEDED(hr)) {
                PWSTR pszFilePath = nullptr;
                hr = pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath);
                if (SUCCEEDED(hr)) {
                    std::string result = toNarrow(pszFilePath);
                    CoTaskMemFree(pszFilePath);
                    pItem->Release();
                    pFileOpen->Release();
                    if (needCoUninit) CoUninitialize();
                    return result;
                }
                pItem->Release();
            }
        }
        pFileOpen->Release();
    }

    // Fallback to SHBrowseForFolder
    BROWSEINFOW bi;
    ZeroMemory(&bi, sizeof(bi));
    bi.hwndOwner = nullptr;
    std::wstring wTitle = toWide(title);
    bi.lpszTitle = wTitle.c_str();
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;

    PIDLIST_ABSOLUTE pidl = SHBrowseForFolderW(&bi);
    if (pidl != nullptr) {
        wchar_t path[MAX_PATH] = { 0 };
        if (SHGetPathFromIDListW(pidl, path)) {
            CoTaskMemFree(pidl);
            if (needCoUninit) CoUninitialize();
            return toNarrow(path);
        }
        CoTaskMemFree(pidl);
    }
    if (needCoUninit) CoUninitialize();
    return "";
#else
    if (hasCommand("zenity")) {
        std::string cmd = "zenity --file-selection --directory --filename=" + escapeShellArg(initialDir) + " --title=" + escapeShellArg(title) + " 2>/dev/null";
        return runCommand(cmd);
    } else if (hasCommand("kdialog")) {
        std::string cmd = "kdialog --getexistingdirectory " + escapeShellArg(initialDir) + " --title " + escapeShellArg(title) + " 2>/dev/null";
        return runCommand(cmd);
    }
    return "";
#endif
}

std::string FileDialog::saveFile(const std::string& title,
                                const std::string& defaultFileName,
                                const std::string& filterDesc,
                                const std::string& filterExt) {
    std::string initialDir = forensivault::core::Platform::getUserHomeDirectory();
    if (!initialDir.empty() && initialDir.back() != '/' && initialDir.back() != '\\') {
        initialDir += '/';
    }

#if defined(_WIN32)
    wchar_t filename[MAX_PATH] = { 0 };
    std::wstring wDefName = toWide(defaultFileName);
    wcsncpy_s(filename, MAX_PATH, wDefName.c_str(), _TRUNCATE);

    std::wstring wTitle = toWide(title);
    std::wstring wDesc = toWide(filterDesc);
    std::wstring wExt = toWide(filterExt);
    std::wstring wInitDir = toWide(initialDir);

    std::vector<wchar_t> filter;
    for (wchar_t c : wDesc) filter.push_back(c);
    filter.push_back(L'\0');
    for (wchar_t c : wExt) filter.push_back(c);
    filter.push_back(L'\0');
    filter.push_back(L'\0');

    OPENFILENAMEW ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = nullptr;
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = filter.data();
    ofn.nFilterIndex = 1;
    ofn.lpstrTitle = wTitle.c_str();
    ofn.lpstrInitialDir = wInitDir.c_str();
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR;

    if (GetSaveFileNameW(&ofn)) {
        return toNarrow(filename);
    }
    return "";
#else
    std::string startPath = initialDir + defaultFileName;
    if (hasCommand("zenity")) {
        std::string cmd = "zenity --file-selection --save --confirm-overwrite --filename=" + escapeShellArg(startPath) + " --title=" + escapeShellArg(title) + " 2>/dev/null";
        return runCommand(cmd);
    } else if (hasCommand("kdialog")) {
        std::string cmd = "kdialog --getsavefilename " + escapeShellArg(startPath) + " --title " + escapeShellArg(title) + " 2>/dev/null";
        return runCommand(cmd);
    }
    return "";
#endif
}

void FileDialog::openFolderInExplorer(const std::string& folderPath) {
#if defined(_WIN32)
    std::wstring wPath = toWide(folderPath);
    ShellExecuteW(nullptr, L"open", wPath.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
#else
    std::string cmd = "xdg-open " + escapeShellArg(folderPath) + " >/dev/null 2>&1 &";
    int ret = std::system(cmd.c_str());
    (void)ret;
#endif
}

} // namespace forensivault::gui
