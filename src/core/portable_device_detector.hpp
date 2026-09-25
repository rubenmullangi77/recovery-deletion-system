#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace forensivault::core {

struct PortableDeviceItem {
    std::string object_id;
    std::string name;
    std::string path;
    bool is_folder{false};
    uint64_t size_bytes{0};
    std::string modified_iso;
    std::string content_type;
    bool can_delete{false};
};

struct PortableDeviceInfo {
    std::string device_id;
    std::string name;             // e.g. "iQOO 7", "Samsung Galaxy"
    std::string manufacturer;     // e.g. "vivo", "Samsung"
    std::string description;      // e.g. "Portable Device"
    std::string protocol;         // "MTP"
    std::string connection_type;  // "USB"
    std::string status;           // "Connected"
    bool is_portable{true};
    std::vector<std::string> storage_names; // e.g. "Internal shared storage", "SD card"
};

class PortableDeviceDetector {
public:
    static std::vector<PortableDeviceInfo> detectPortableDevices();
    static std::string detectPortableDevicesJson();
    static std::string browseDeviceJson(const std::string& deviceId, const std::string& objectId);
    static std::string deleteDeviceFileJson(const std::string& deviceId, const std::string& objectId, const std::string& parentObjectId = "");
    static std::string copyDeviceFileJson(const std::string& deviceId, const std::string& objectId, const std::string& destinationDirectory);
};

} // namespace forensivault::core
