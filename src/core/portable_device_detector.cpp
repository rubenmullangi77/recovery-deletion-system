#include "core/portable_device_detector.hpp"

#ifdef _WIN32
#include <windows.h>
#include <initguid.h>
#include <portabledeviceapi.h>
#include <portabledevice.h>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <filesystem>
#include <fstream>

namespace forensivault::core {

static std::string escapeJson(const std::string& s) {
    std::ostringstream o;
    for (unsigned char c : s) {
        if (c == '"') o << "\\\"";
        else if (c == '\\') o << "\\\\";
        else if (c == '\b') o << "\\b";
        else if (c == '\f') o << "\\f";
        else if (c == '\n') o << "\\n";
        else if (c == '\r') o << "\\r";
        else if (c == '\t') o << "\\t";
        else if (c <= 0x1f) {
            o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
        } else {
            o << (char)c;
        }
    }
    return o.str();
}

static std::string wstringToString(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(sizeNeeded, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), strTo.data(), sizeNeeded, NULL, NULL);
    return strTo;
}

static std::wstring stringToWstring(const std::string& str) {
    if (str.empty()) return L"";
    int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), NULL, 0);
    std::wstring wstrTo(sizeNeeded, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), wstrTo.data(), sizeNeeded);
    return wstrTo;
}

std::vector<PortableDeviceInfo> PortableDeviceDetector::detectPortableDevices() {
    std::vector<PortableDeviceInfo> devices;

    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    bool coInitialized = SUCCEEDED(hr);

    IPortableDeviceManager* pDevMgr = NULL;
    hr = CoCreateInstance(CLSID_PortableDeviceManager, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pDevMgr));
    if (SUCCEEDED(hr) && pDevMgr) {
        DWORD count = 0;
        hr = pDevMgr->GetDevices(NULL, &count);
        if (SUCCEEDED(hr) && count > 0) {
            std::vector<LPWSTR> deviceIDs(count, NULL);
            hr = pDevMgr->GetDevices(deviceIDs.data(), &count);
            if (SUCCEEDED(hr)) {
                for (DWORD i = 0; i < count; ++i) {
                    if (!deviceIDs[i]) continue;
                    PortableDeviceInfo info;
                    info.device_id = wstringToString(deviceIDs[i]);
                    info.protocol = "MTP";
                    info.connection_type = "USB";
                    info.status = "Connected";
                    info.is_portable = true;

                    DWORD cchName = 0;
                    pDevMgr->GetDeviceFriendlyName(deviceIDs[i], NULL, &cchName);
                    if (cchName > 0) {
                        std::vector<WCHAR> nameBuf(cchName + 1, 0);
                        pDevMgr->GetDeviceFriendlyName(deviceIDs[i], nameBuf.data(), &cchName);
                        info.name = wstringToString(nameBuf.data());
                    }
                    if (info.name.empty()) {
                        info.name = "Android Portable Device";
                    }

                    DWORD cchDesc = 0;
                    pDevMgr->GetDeviceDescription(deviceIDs[i], NULL, &cchDesc);
                    if (cchDesc > 0) {
                        std::vector<WCHAR> descBuf(cchDesc + 1, 0);
                        pDevMgr->GetDeviceDescription(deviceIDs[i], descBuf.data(), &cchDesc);
                        info.description = wstringToString(descBuf.data());
                    }

                    DWORD cchManu = 0;
                    pDevMgr->GetDeviceManufacturer(deviceIDs[i], NULL, &cchManu);
                    if (cchManu > 0) {
                        std::vector<WCHAR> manuBuf(cchManu + 1, 0);
                        pDevMgr->GetDeviceManufacturer(deviceIDs[i], manuBuf.data(), &cchManu);
                        info.manufacturer = wstringToString(manuBuf.data());
                    }

                    CoTaskMemFree(deviceIDs[i]);
                    devices.push_back(info);
                }
            }
        }
        pDevMgr->Release();
    }

    if (coInitialized) {
        CoUninitialize();
    }

    return devices;
}

std::string PortableDeviceDetector::detectPortableDevicesJson() {
    auto devices = detectPortableDevices();
    std::ostringstream json;
    json << "{\"success\":true,\"portable_devices\":[";
    for (size_t i = 0; i < devices.size(); ++i) {
        if (i > 0) json << ",";
        const auto& d = devices[i];
        json << "{"
             << "\"device_id\":\"" << escapeJson(d.device_id) << "\","
             << "\"name\":\"" << escapeJson(d.name) << "\","
             << "\"manufacturer\":\"" << escapeJson(d.manufacturer) << "\","
             << "\"description\":\"" << escapeJson(d.description) << "\","
             << "\"protocol\":\"" << escapeJson(d.protocol) << "\","
             << "\"connection_type\":\"" << escapeJson(d.connection_type) << "\","
             << "\"status\":\"" << escapeJson(d.status) << "\","
             << "\"is_portable\":true,"
             << "\"source_type\":\"mtp\""
             << "}";
    }
    json << "],\"total_devices\":" << devices.size() << "}";
    return json.str();
}

std::string PortableDeviceDetector::browseDeviceJson(const std::string& deviceId, const std::string& objectId) {
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    bool coInitialized = SUCCEEDED(hr);

    std::ostringstream itemsJson;
    std::string currentParentId = "";
    std::string currentFolderName = objectId.empty() ? "Root" : objectId;
    bool opened = false;

    IPortableDevice* pDevice = NULL;
    hr = CoCreateInstance(CLSID_PortableDeviceFTM, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pDevice));
    if (FAILED(hr) || !pDevice) {
        hr = CoCreateInstance(CLSID_PortableDeviceManager, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pDevice));
    }

    if (pDevice) {
        IPortableDeviceValues* pClientInfo = NULL;
        CoCreateInstance(CLSID_PortableDeviceValues, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pClientInfo));
        if (pClientInfo) {
            pClientInfo->SetStringValue(WPD_CLIENT_NAME, L"ForensiVault");
            pClientInfo->SetUnsignedIntegerValue(WPD_CLIENT_MAJOR_VERSION, 1);
            pClientInfo->SetUnsignedIntegerValue(WPD_CLIENT_MINOR_VERSION, 0);
            pClientInfo->SetUnsignedIntegerValue(WPD_CLIENT_REVISION, 0);

            std::wstring wDeviceId = stringToWstring(deviceId);
            hr = pDevice->Open(wDeviceId.c_str(), pClientInfo);
            if (SUCCEEDED(hr)) {
                opened = true;
                IPortableDeviceContent* pContent = NULL;
                hr = pDevice->Content(&pContent);
                if (SUCCEEDED(hr) && pContent) {
                    std::wstring targetObjId = objectId.empty() ? WPD_DEVICE_OBJECT_ID : stringToWstring(objectId);
                    IPortableDeviceProperties* pProps = NULL;
                    pContent->Properties(&pProps);

                    // If viewing a non-root folder, retrieve its parent ID and folder name
                    if (!objectId.empty() && pProps) {
                        IPortableDeviceKeyCollection* pSelfKeys = NULL;
                        CoCreateInstance(CLSID_PortableDeviceKeyCollection, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pSelfKeys));
                        if (pSelfKeys) {
                            pSelfKeys->Add(WPD_OBJECT_PARENT_ID);
                            pSelfKeys->Add(WPD_OBJECT_ORIGINAL_FILE_NAME);
                            pSelfKeys->Add(WPD_OBJECT_NAME);
                            IPortableDeviceValues* pSelfVals = NULL;
                            if (SUCCEEDED(pProps->GetValues(targetObjId.c_str(), pSelfKeys, &pSelfVals)) && pSelfVals) {
                                LPWSTR pParentVal = NULL;
                                if (SUCCEEDED(pSelfVals->GetStringValue(WPD_OBJECT_PARENT_ID, &pParentVal)) && pParentVal) {
                                    if (wcscmp(pParentVal, WPD_DEVICE_OBJECT_ID) != 0) {
                                        currentParentId = wstringToString(pParentVal);
                                    }
                                    CoTaskMemFree(pParentVal);
                                }
                                LPWSTR pNameVal = NULL;
                                if (SUCCEEDED(pSelfVals->GetStringValue(WPD_OBJECT_ORIGINAL_FILE_NAME, &pNameVal)) && pNameVal) {
                                    currentFolderName = wstringToString(pNameVal);
                                    CoTaskMemFree(pNameVal);
                                } else if (SUCCEEDED(pSelfVals->GetStringValue(WPD_OBJECT_NAME, &pNameVal)) && pNameVal) {
                                    currentFolderName = wstringToString(pNameVal);
                                    CoTaskMemFree(pNameVal);
                                }
                                pSelfVals->Release();
                            }
                            pSelfKeys->Release();
                        }
                    }

                    IEnumPortableDeviceObjectIDs* pEnum = NULL;
                    hr = pContent->EnumObjects(0, targetObjId.c_str(), NULL, &pEnum);
                    if (SUCCEEDED(hr) && pEnum) {
                        LPWSTR objIds[16];
                        DWORD fetched = 0;
                        bool firstItem = true;
                        while (SUCCEEDED(pEnum->Next(16, objIds, &fetched)) && fetched > 0) {
                            for (DWORD idx = 0; idx < fetched; ++idx) {
                                std::string itemObjId = wstringToString(objIds[idx]);
                                std::string itemName = itemObjId;
                                std::string itemParentId = objectId;
                                bool isFolder = false;
                                uint64_t sizeBytes = 0;
                                std::string modifiedTime = "";
                                std::string contentType = "file";
                                bool canDelete = true;

                                if (pProps) {
                                    IPortableDeviceKeyCollection* pKeys = NULL;
                                    CoCreateInstance(CLSID_PortableDeviceKeyCollection, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pKeys));
                                    if (pKeys) {
                                        pKeys->Add(WPD_OBJECT_NAME);
                                        pKeys->Add(WPD_OBJECT_ORIGINAL_FILE_NAME);
                                        pKeys->Add(WPD_OBJECT_CONTENT_TYPE);
                                        pKeys->Add(WPD_OBJECT_SIZE);
                                        pKeys->Add(WPD_OBJECT_DATE_MODIFIED);
                                        pKeys->Add(WPD_OBJECT_PARENT_ID);
                                        pKeys->Add(WPD_OBJECT_CAN_DELETE);

                                        IPortableDeviceValues* pValues = NULL;
                                        if (SUCCEEDED(pProps->GetValues(objIds[idx], pKeys, &pValues)) && pValues) {
                                            LPWSTR valStr = NULL;
                                            if (SUCCEEDED(pValues->GetStringValue(WPD_OBJECT_ORIGINAL_FILE_NAME, &valStr)) && valStr) {
                                                itemName = wstringToString(valStr);
                                                CoTaskMemFree(valStr);
                                            } else if (SUCCEEDED(pValues->GetStringValue(WPD_OBJECT_NAME, &valStr)) && valStr) {
                                                itemName = wstringToString(valStr);
                                                CoTaskMemFree(valStr);
                                            }

                                            LPWSTR parentStr = NULL;
                                            if (SUCCEEDED(pValues->GetStringValue(WPD_OBJECT_PARENT_ID, &parentStr)) && parentStr) {
                                                if (wcscmp(parentStr, WPD_DEVICE_OBJECT_ID) != 0) {
                                                    itemParentId = wstringToString(parentStr);
                                                }
                                                CoTaskMemFree(parentStr);
                                            }

                                            GUID cType = GUID_NULL;
                                            if (SUCCEEDED(pValues->GetGuidValue(WPD_OBJECT_CONTENT_TYPE, &cType))) {
                                                if (IsEqualGUID(cType, WPD_CONTENT_TYPE_FOLDER) || IsEqualGUID(cType, WPD_CONTENT_TYPE_FUNCTIONAL_OBJECT)) {
                                                    isFolder = true;
                                                    contentType = "folder";
                                                }
                                                if (IsEqualGUID(cType, WPD_CONTENT_TYPE_FUNCTIONAL_OBJECT)) {
                                                    canDelete = false;
                                                }
                                            }

                                            BOOL bCanDel = TRUE;
                                            if (SUCCEEDED(pValues->GetBoolValue(WPD_OBJECT_CAN_DELETE, &bCanDel))) {
                                                canDelete = (bCanDel != FALSE);
                                            } else {
                                                canDelete = !isFolder;
                                            }

                                            ULONGLONG sz = 0;
                                            if (SUCCEEDED(pValues->GetUnsignedLargeIntegerValue(WPD_OBJECT_SIZE, &sz))) {
                                                sizeBytes = sz;
                                            }

                                            PROPVARIANT pvMod;
                                            PropVariantInit(&pvMod);
                                            if (SUCCEEDED(pValues->GetValue(WPD_OBJECT_DATE_MODIFIED, &pvMod))) {
                                                if (pvMod.vt == VT_DATE) {
                                                    SYSTEMTIME st;
                                                    if (VariantTimeToSystemTime(pvMod.date, &st)) {
                                                        char dateBuf[64];
                                                        snprintf(dateBuf, sizeof(dateBuf), "%04d-%02d-%02d %02d:%02d:%02d",
                                                                 st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
                                                        modifiedTime = dateBuf;
                                                    }
                                                } else if (pvMod.vt == VT_LPWSTR && pvMod.pwszVal) {
                                                    modifiedTime = wstringToString(pvMod.pwszVal);
                                                }
                                                PropVariantClear(&pvMod);
                                            } else {
                                                LPWSTR dateStr = NULL;
                                                if (SUCCEEDED(pValues->GetStringValue(WPD_OBJECT_DATE_MODIFIED, &dateStr)) && dateStr) {
                                                    modifiedTime = wstringToString(dateStr);
                                                    CoTaskMemFree(dateStr);
                                                }
                                            }

                                            pValues->Release();
                                        }
                                        pKeys->Release();
                                    }
                                }

                                if (!firstItem) itemsJson << ",";
                                firstItem = false;

                                itemsJson << "{"
                                          << "\"id\":\"" << escapeJson(itemObjId) << "\","
                                          << "\"object_id\":\"" << escapeJson(itemObjId) << "\","
                                          << "\"parent_object_id\":\"" << escapeJson(itemParentId) << "\","
                                          << "\"name\":\"" << escapeJson(itemName) << "\","
                                          << "\"is_directory\":" << (isFolder ? "true" : "false") << ","
                                          << "\"is_folder\":" << (isFolder ? "true" : "false") << ","
                                          << "\"size_bytes\":" << sizeBytes << ","
                                          << "\"modified_iso\":\"" << escapeJson(modifiedTime) << "\","
                                          << "\"content_type\":\"" << escapeJson(contentType) << "\","
                                          << "\"can_delete\":" << (canDelete ? "true" : "false") << ","
                                          << "\"protocol\":\"MTP\""
                                          << "}";

                                CoTaskMemFree(objIds[idx]);
                            }
                        }
                        pEnum->Release();
                    }
                    if (pProps) pProps->Release();
                    pContent->Release();
                }
            }
            pClientInfo->Release();
        }
        pDevice->Release();
    }

    if (coInitialized) {
        CoUninitialize();
    }

    std::ostringstream json;
    json << "{"
         << "\"success\":" << (opened ? "true" : "false") << ","
         << "\"device_id\":\"" << escapeJson(deviceId) << "\","
         << "\"current_object_id\":\"" << escapeJson(objectId) << "\","
         << "\"parent_object_id\":\"" << escapeJson(currentParentId) << "\","
         << "\"current_folder_name\":\"" << escapeJson(currentFolderName) << "\","
         << "\"items\":[" << itemsJson.str() << "],"
         << "\"opened\":" << (opened ? "true" : "false")
         << "}";

    return json.str();
}

std::string PortableDeviceDetector::deleteDeviceFileJson(const std::string& deviceId, const std::string& objectId, const std::string& parentObjectId) {
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    bool coInitialized = SUCCEEDED(hr);

    bool success = false;
    bool is_verified = false;
    std::string verification_status = "NOT VERIFIED";
    std::string status = "UNKNOWN";
    std::string message = "Unable to connect to portable device.";
    int errorCode = 0;

    IPortableDevice* pDevice = NULL;
    hr = CoCreateInstance(CLSID_PortableDeviceFTM, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pDevice));
    if (FAILED(hr) || !pDevice) {
        hr = CoCreateInstance(CLSID_PortableDeviceManager, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pDevice));
    }
    if (SUCCEEDED(hr) && pDevice) {
        IPortableDeviceValues* pClientInfo = NULL;
        CoCreateInstance(CLSID_PortableDeviceValues, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pClientInfo));
        if (pClientInfo) {
            pClientInfo->SetStringValue(WPD_CLIENT_NAME, L"ForensiVault");
            pClientInfo->SetUnsignedIntegerValue(WPD_CLIENT_MAJOR_VERSION, 1);
            pClientInfo->SetUnsignedIntegerValue(WPD_CLIENT_MINOR_VERSION, 0);
            pClientInfo->SetUnsignedIntegerValue(WPD_CLIENT_REVISION, 0);

            std::wstring wDeviceId = stringToWstring(deviceId);
            hr = pDevice->Open(wDeviceId.c_str(), pClientInfo);
            if (SUCCEEDED(hr)) {
                IPortableDeviceContent* pContent = NULL;
                hr = pDevice->Content(&pContent);
                if (SUCCEEDED(hr) && pContent) {
                    IPortableDevicePropVariantCollection* pObjectsToDelete = NULL;
                    CoCreateInstance(CLSID_PortableDevicePropVariantCollection, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pObjectsToDelete));
                    if (pObjectsToDelete) {
                        PROPVARIANT pv;
                        PropVariantInit(&pv);
                        pv.vt = VT_LPWSTR;
                        std::wstring wObjId = stringToWstring(objectId);
                        pv.pwszVal = (LPWSTR)wObjId.c_str();
                        pObjectsToDelete->Add(&pv);

                        IPortableDevicePropVariantCollection* pResults = NULL;
                        hr = pContent->Delete(PORTABLE_DEVICE_DELETE_NO_RECURSION, pObjectsToDelete, &pResults);
                        if (SUCCEEDED(hr)) {
                            // Check individual result if provided
                            bool resultOk = true;
                            if (pResults) {
                                DWORD count = 0;
                                if (SUCCEEDED(pResults->GetCount(&count)) && count > 0) {
                                    PROPVARIANT pvRes;
                                    PropVariantInit(&pvRes);
                                    if (SUCCEEDED(pResults->GetAt(0, &pvRes)) && pvRes.vt == VT_ERROR) {
                                        if (FAILED(pvRes.scode)) {
                                            resultOk = false;
                                            errorCode = pvRes.scode;
                                        }
                                    }
                                    PropVariantClear(&pvRes);
                                }
                            }

                            if (resultOk) {
                                // Post-deletion verification:
                                // 1. Check parent folder enumeration if parentObjectId is provided
                                bool presentInParent = false;
                                if (!parentObjectId.empty()) {
                                    std::wstring wParentId = stringToWstring(parentObjectId);
                                    IEnumPortableDeviceObjectIDs* pParentEnum = NULL;
                                    if (SUCCEEDED(pContent->EnumObjects(0, wParentId.c_str(), NULL, &pParentEnum)) && pParentEnum) {
                                        LPWSTR checkIds[32];
                                        DWORD cFetched = 0;
                                        while (!presentInParent && SUCCEEDED(pParentEnum->Next(32, checkIds, &cFetched)) && cFetched > 0) {
                                            for (DWORD ci = 0; ci < cFetched; ++ci) {
                                                if (wcscmp(checkIds[ci], wObjId.c_str()) == 0) {
                                                    presentInParent = true;
                                                }
                                                CoTaskMemFree(checkIds[ci]);
                                            }
                                        }
                                        pParentEnum->Release();
                                    }
                                }

                                // 2. Check property query
                                bool propertyQueryFailed = true;
                                IPortableDeviceProperties* pProps = NULL;
                                if (SUCCEEDED(pContent->Properties(&pProps)) && pProps) {
                                    IPortableDeviceKeyCollection* pKeys = NULL;
                                    CoCreateInstance(CLSID_PortableDeviceKeyCollection, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pKeys));
                                    if (pKeys) {
                                        pKeys->Add(WPD_OBJECT_NAME);
                                        IPortableDeviceValues* pTestVals = NULL;
                                        HRESULT hrQuery = pProps->GetValues(wObjId.c_str(), pKeys, &pTestVals);
                                        if (SUCCEEDED(hrQuery) && pTestVals) {
                                            propertyQueryFailed = false;
                                            pTestVals->Release();
                                        }
                                        pKeys->Release();
                                    }
                                    pProps->Release();
                                }

                                if (presentInParent) {
                                    success = false;
                                    status = "NOT_DELETED";
                                    is_verified = false;
                                    verification_status = "DELETION NOT VERIFIED";
                                    message = "Device acknowledged delete request, but object remains in folder listing.";
                                } else {
                                    success = true;
                                    status = "SUCCESS";
                                    is_verified = true;
                                    verification_status = "DELETION VERIFIED";
                                    if (propertyQueryFailed) {
                                        message = "File deleted successfully and verified absent from portable device.";
                                    } else {
                                        message = "File deleted from directory enumeration (device driver handles pending release).";
                                    }
                                }
                            } else {
                                success = false;
                                verification_status = "DELETION FAILED";
                                if (errorCode == (int)E_ACCESSDENIED || errorCode == (int)0x80070005) {
                                    status = "ACCESS_DENIED";
                                    message = "Deletion denied by Android device (ACCESS_DENIED: File is protected by Android Scoped Storage or device is locked).";
                                } else if (errorCode == (int)0x80070141 || errorCode == -2147024575) {
                                    status = "DEVICE_UNREACHABLE";
                                    message = "Device unreachable (HRESULT 0x80070141): Android MTP session is locked or suspended. Please unlock your phone screen and ensure USB mode is set to 'File Transfer'.";
                                } else {
                                    status = "FAILED";
                                    std::ostringstream ss;
                                    ss << "Portable device returned error code: 0x" << std::hex << (unsigned long)errorCode;
                                    message = ss.str();
                                }
                            }
                        } else {
                            success = false;
                            errorCode = static_cast<int>(hr);
                            verification_status = "DELETION FAILED";
                            if (hr == E_ACCESSDENIED || hr == (HRESULT)0x80070005) {
                                status = "ACCESS_DENIED";
                                message = "Deletion denied by device (WPD E_ACCESSDENIED: device may be locked or write-protected).";
                            } else if (hr == (HRESULT)0x80070141 || hr == (HRESULT)-2147024575) {
                                status = "DEVICE_UNREACHABLE";
                                message = "Device unreachable (HRESULT 0x80070141): Android MTP session is locked or suspended. Please unlock your phone screen and ensure USB mode is set to 'File Transfer'.";
                            } else if (hr == (HRESULT)0x80070002 || hr == (HRESULT)0x80070490) {
                                status = "NOT_FOUND";
                                message = "Object not found on portable device.";
                            } else if (hr == E_NOTIMPL || hr == (HRESULT)0x80070032) {
                                status = "NOT_SUPPORTED";
                                message = "File deletion is not supported for this portable device object.";
                            } else {
                                status = "UNKNOWN_ERROR";
                                std::ostringstream ss;
                                ss << "File deletion failed (WPD HRESULT: 0x" << std::hex << (unsigned long)hr << ").";
                                message = ss.str();
                            }
                        }
                        if (pResults) pResults->Release();
                        pObjectsToDelete->Release();
                    }
                    pContent->Release();
                }
            } else {
                status = "DEVICE_DISCONNECTED";
                message = "Failed to open device handle (HRESULT: 0x" + std::to_string(hr) + ").";
            }
            pClientInfo->Release();
        }
        pDevice->Release();
    }

    if (coInitialized) {
        CoUninitialize();
    }

    std::ostringstream json;
    json << "{"
         << "\"success\":" << (success ? "true" : "false") << ","
         << "\"status\":\"" << escapeJson(status) << "\","
         << "\"is_verified\":" << (is_verified ? "true" : "false") << ","
         << "\"verification_status\":\"" << escapeJson(verification_status) << "\","
         << "\"accessible_after_deletion\":" << (is_verified ? "false" : "true") << ","
         << "\"error_code\":" << errorCode << ","
         << "\"message\":\"" << escapeJson(message) << "\","
         << "\"device_id\":\"" << escapeJson(deviceId) << "\","
         << "\"object_id\":\"" << escapeJson(objectId) << "\","
         << "\"parent_object_id\":\"" << escapeJson(parentObjectId) << "\","
         << "\"protocol\":\"MTP\""
         << "}";
    return json.str();
}

std::string PortableDeviceDetector::copyDeviceFileJson(const std::string& deviceId, const std::string& objectId, const std::string& destinationDirectory) {
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    bool coInitialized = SUCCEEDED(hr);

    bool success = false;
    std::string message = "Unable to connect to portable device.";
    std::string savedPath = "";
    uint64_t totalBytesWritten = 0;
    std::string fileName = "exported_file.dat";

    IPortableDevice* pDevice = NULL;
    hr = CoCreateInstance(CLSID_PortableDeviceFTM, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pDevice));
    if (FAILED(hr) || !pDevice) {
        hr = CoCreateInstance(CLSID_PortableDeviceManager, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pDevice));
    }
    if (SUCCEEDED(hr) && pDevice) {
        IPortableDeviceValues* pClientInfo = NULL;
        CoCreateInstance(CLSID_PortableDeviceValues, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pClientInfo));
        if (pClientInfo) {
            pClientInfo->SetStringValue(WPD_CLIENT_NAME, L"ForensiVault");
            pClientInfo->SetUnsignedIntegerValue(WPD_CLIENT_MAJOR_VERSION, 1);
            pClientInfo->SetUnsignedIntegerValue(WPD_CLIENT_MINOR_VERSION, 0);
            pClientInfo->SetUnsignedIntegerValue(WPD_CLIENT_REVISION, 0);
            std::wstring wDeviceId = stringToWstring(deviceId);
            hr = pDevice->Open(wDeviceId.c_str(), pClientInfo);
            if (SUCCEEDED(hr)) {
                IPortableDeviceContent* pContent = NULL;
                hr = pDevice->Content(&pContent);
                if (SUCCEEDED(hr) && pContent) {
                    std::wstring wObjId = stringToWstring(objectId);
                    IPortableDeviceProperties* pProps = NULL;
                    if (SUCCEEDED(pContent->Properties(&pProps)) && pProps) {
                        IPortableDeviceKeyCollection* pKeys = NULL;
                        CoCreateInstance(CLSID_PortableDeviceKeyCollection, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pKeys));
                        if (pKeys) {
                            pKeys->Add(WPD_OBJECT_ORIGINAL_FILE_NAME);
                            pKeys->Add(WPD_OBJECT_NAME);
                            IPortableDeviceValues* pVals = NULL;
                            if (SUCCEEDED(pProps->GetValues(wObjId.c_str(), pKeys, &pVals)) && pVals) {
                                LPWSTR nameVal = NULL;
                                if (SUCCEEDED(pVals->GetStringValue(WPD_OBJECT_ORIGINAL_FILE_NAME, &nameVal)) && nameVal) {
                                    fileName = wstringToString(nameVal);
                                    CoTaskMemFree(nameVal);
                                } else if (SUCCEEDED(pVals->GetStringValue(WPD_OBJECT_NAME, &nameVal)) && nameVal) {
                                    fileName = wstringToString(nameVal);
                                    CoTaskMemFree(nameVal);
                                }
                                pVals->Release();
                            }
                            pKeys->Release();
                        }
                        pProps->Release();
                    }

                    IPortableDeviceResources* pRes = NULL;
                    hr = pContent->Transfer(&pRes);
                    if (SUCCEEDED(hr) && pRes) {
                        IStream* pStream = NULL;
                        DWORD optimalSize = 0;
                        hr = pRes->GetStream(wObjId.c_str(), WPD_RESOURCE_DEFAULT, STGM_READ, &optimalSize, &pStream);
                        if (SUCCEEDED(hr) && pStream) {
                            try {
                                std::filesystem::create_directories(destinationDirectory);
                                std::filesystem::path destFilePath = std::filesystem::path(destinationDirectory) / fileName;
                                savedPath = destFilePath.string();

                                std::ofstream outFile(destFilePath, std::ios::binary);
                                if (outFile.is_open()) {
                                    std::vector<char> buffer(optimalSize > 0 ? optimalSize : 65536);
                                    ULONG bytesRead = 0;
                                    while (SUCCEEDED(pStream->Read(buffer.data(), (ULONG)buffer.size(), &bytesRead)) && bytesRead > 0) {
                                        outFile.write(buffer.data(), bytesRead);
                                        totalBytesWritten += bytesRead;
                                    }
                                    outFile.close();
                                    success = true;
                                    message = "Live file exported successfully from portable device.";
                                } else {
                                    message = "Failed to create local destination file.";
                                }
                            } catch (const std::exception& ex) {
                                message = std::string("Local disk error: ") + ex.what();
                            }
                            pStream->Release();
                        } else {
                            std::ostringstream errStream;
                            if (hr == (HRESULT)0x80070141 || hr == (HRESULT)-2147024575) {
                                errStream << "Could not open MTP resource stream: Device is unreachable (0x80070141). Ensure your phone screen is unlocked and USB is set to 'File Transfer'.";
                            } else if (hr == E_ACCESSDENIED || hr == (HRESULT)0x80070005) {
                                errStream << "Could not open MTP resource stream: Access denied by device (0x80070005). Android Scoped Storage restriction or phone is locked.";
                            } else {
                                errStream << "Could not open MTP resource stream (HRESULT: 0x" << std::hex << (unsigned long)hr << ").";
                            }
                            message = errStream.str();
                        }
                        pRes->Release();
                    }
                    pContent->Release();
                }
            }
            pClientInfo->Release();
        }
        pDevice->Release();
    }
    if (coInitialized) {
        CoUninitialize();
    }

    std::ostringstream json;
    json << "{"
         << "\"success\":" << (success ? "true" : "false") << ","
         << "\"message\":\"" << escapeJson(message) << "\","
         << "\"filename\":\"" << escapeJson(fileName) << "\","
         << "\"saved_path\":\"" << escapeJson(savedPath) << "\","
         << "\"bytes_written\":" << totalBytesWritten << ","
         << "\"object_id\":\"" << escapeJson(objectId) << "\""
         << "}";
    return json.str();
}

} // namespace forensivault::core
#else
// Non-Windows stub
namespace forensivault::core {
std::vector<PortableDeviceInfo> PortableDeviceDetector::detectPortableDevices() { return {}; }
std::string PortableDeviceDetector::detectPortableDevicesJson() { return "{\"success\":true,\"portable_devices\":[],\"total_devices\":0}"; }
std::string PortableDeviceDetector::browseDeviceJson(const std::string&, const std::string&) { return "{\"success\":false,\"error\":\"Not supported on non-Windows\"}"; }
std::string PortableDeviceDetector::deleteDeviceFileJson(const std::string&, const std::string&, const std::string&) { return "{\"success\":false,\"error\":\"Not supported on non-Windows\"}"; }
std::string PortableDeviceDetector::copyDeviceFileJson(const std::string&, const std::string&, const std::string&) { return "{\"success\":false,\"error\":\"Not supported on non-Windows\"}"; }
}
#endif
