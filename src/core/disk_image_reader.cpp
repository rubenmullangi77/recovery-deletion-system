#include "core/disk_image_reader.hpp"
#include <system_error>
#include <limits>
#include <iostream>
#include <cstring>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#elif defined(__linux__)
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace forensivault::core {

DiskImageReader::DiskImageReader() = default;

DiskImageReader::DiskImageReader(const std::string& filepath, uint32_t sectorSize) {
    open(filepath, sectorSize);
}

DiskImageReader::~DiskImageReader() {
    close();
}

DiskImageReader::DiskImageReader(DiskImageReader&& other) noexcept {
    std::lock_guard<std::mutex> lock(other.ioMutex_);
    filepath_ = std::move(other.filepath_);
    sectorSize_ = other.sectorSize_;
    fileSize_ = other.fileSize_;
    totalSectors_ = other.totalSectors_;
    stream_ = std::move(other.stream_);
    winDeviceHandle_ = other.winDeviceHandle_;
    currentOffset_ = other.currentOffset_;
    lastError_ = std::move(other.lastError_);

    other.winDeviceHandle_ = nullptr;
    other.fileSize_ = 0;
    other.totalSectors_ = 0;
    other.currentOffset_ = 0;
}

DiskImageReader& DiskImageReader::operator=(DiskImageReader&& other) noexcept {
    if (this != &other) {
        std::scoped_lock lock(ioMutex_, other.ioMutex_);
        close();
        filepath_ = std::move(other.filepath_);
        sectorSize_ = other.sectorSize_;
        fileSize_ = other.fileSize_;
        totalSectors_ = other.totalSectors_;
        stream_ = std::move(other.stream_);
        winDeviceHandle_ = other.winDeviceHandle_;
        currentOffset_ = other.currentOffset_;
        lastError_ = std::move(other.lastError_);

        other.winDeviceHandle_ = nullptr;
        other.fileSize_ = 0;
        other.totalSectors_ = 0;
        other.currentOffset_ = 0;
    }
    return *this;
}

bool DiskImageReader::open(const std::string& filepath, uint32_t sectorSize) {
    std::lock_guard<std::mutex> lock(ioMutex_);
    close();
    clearError();

    if (filepath.empty()) {
        setError("Cannot open disk image: empty filepath provided");
        return false;
    }

    if (sectorSize == 0) {
        setError("Invalid sector size: sector size must be greater than zero");
        return false;
    }

    filepath_ = filepath;
    sectorSize_ = sectorSize;

#if defined(_WIN32)
    // 1. Check for Windows raw device namespaces or logical drive letters (e.g. D:, D:\, \\.\PhysicalDrive0, \\.\D:)
    std::string devPath = filepath_;
    bool isDriveLetter = (devPath.size() == 2 && devPath[1] == ':') ||
                         (devPath.size() == 3 && devPath[1] == ':' && (devPath[2] == '\\' || devPath[2] == '/'));
    if (isDriveLetter) {
        devPath = "\\\\.\\" + devPath.substr(0, 2);
    }
    bool isWinDevice = (devPath.rfind("\\\\.\\", 0) == 0) || (devPath.rfind("\\\\?\\", 0) == 0);
    if (isWinDevice) {
        std::wstring wPath(devPath.begin(), devPath.end());
        HANDLE hDevice = CreateFileW(
            wPath.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        if (hDevice == INVALID_HANDLE_VALUE) {
            DWORD dwErr = GetLastError();
            if (dwErr == ERROR_ACCESS_DENIED) {
                setErrorWithCode("Windows Access Denied (Error 5): Direct sector-level access to raw drive/volume '" + filepath_ +
                                 "' requires administrative elevation (Run as Administrator).", 5);
            } else if (dwErr == ERROR_FILE_NOT_FOUND) {
                setErrorWithCode("Storage device not found (Windows Error 2): " + filepath_, 2);
            } else {
                setErrorWithCode("Failed to open storage device '" + filepath_ + "' (Windows Error " + std::to_string(dwErr) + ")", dwErr);
            }
            return false;
        }

        // Query size of the raw storage device or volume
        DWORD bytesRet = 0;
        GET_LENGTH_INFORMATION lengthInfo = {0};
        if (DeviceIoControl(hDevice, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &lengthInfo, sizeof(lengthInfo), &bytesRet, NULL) && lengthInfo.Length.QuadPart > 0) {
            fileSize_ = lengthInfo.Length.QuadPart;
            DISK_GEOMETRY geom = {0};
            if (DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &geom, sizeof(geom), &bytesRet, NULL) && geom.BytesPerSector > 0) {
                sectorSize_ = geom.BytesPerSector;
            }
        } else {
            DISK_GEOMETRY_EX geomEx = {0};
            if (DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0, &geomEx, sizeof(geomEx), &bytesRet, NULL)) {
                fileSize_ = geomEx.DiskSize.QuadPart;
                if (geomEx.Geometry.BytesPerSector > 0) {
                    sectorSize_ = geomEx.Geometry.BytesPerSector;
                }
            } else {
                LARGE_INTEGER liSize = {0};
                if (GetFileSizeEx(hDevice, &liSize) && liSize.QuadPart > 0) {
                    fileSize_ = liSize.QuadPart;
                } else {
                    DISK_GEOMETRY geom = {0};
                    if (DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &geom, sizeof(geom), &bytesRet, NULL)) {
                        fileSize_ = geom.Cylinders.QuadPart * geom.TracksPerCylinder * geom.SectorsPerTrack * geom.BytesPerSector;
                        if (geom.BytesPerSector > 0) {
                            sectorSize_ = geom.BytesPerSector;
                        }
                    }
                }
            }
        }

        totalSectors_ = (fileSize_ + sectorSize_ - 1) / sectorSize_;
        winDeviceHandle_ = reinterpret_cast<void*>(hDevice);
        currentOffset_ = 0;
        return true;
    }
#endif

#if defined(__linux__)
    // 2. Check for Linux block devices (/dev/sd*, /dev/nvme*, /dev/loop*, etc.)
    struct stat st{};
    if (::stat(filepath_.c_str(), &st) == 0 && S_ISBLK(st.st_mode)) {
        int fd = ::open(filepath_.c_str(), O_RDONLY);
        if (fd < 0) {
            setError("Failed to open Linux block device '" + filepath_ + "': " + std::strerror(errno));
            return false;
        }
        uint64_t blkSize = 0;
        if (::ioctl(fd, BLKGETSIZE64, &blkSize) == 0 && blkSize > 0) {
            fileSize_ = blkSize;
        }
        int secSz = 0;
        if (::ioctl(fd, BLKSSZGET, &secSz) == 0 && secSz > 0) {
            sectorSize_ = static_cast<uint32_t>(secSz);
        }
        ::close(fd);
        totalSectors_ = (fileSize_ + sectorSize_ - 1) / sectorSize_;

        stream_ = std::make_unique<std::ifstream>(filepath_, std::ios::binary | std::ios::in);
        if (!stream_ || !stream_->is_open()) {
            setError("Failed to open block device stream for '" + filepath_ + "'");
            stream_.reset();
            return false;
        }
        currentOffset_ = 0;
        return true;
    }
#endif

    // 3. Open standard disk image file (.img, .dd, .raw) in binary read-only mode
    stream_ = std::make_unique<std::ifstream>(filepath_, std::ios::binary | std::ios::in);
    if (!stream_ || !stream_->is_open()) {
        setError("Failed to open image file '" + filepath_ + "' in binary read-only mode");
        stream_.reset();
        return false;
    }

    // Determine file size
    stream_->seekg(0, std::ios::end);
    std::streamoff endPos = stream_->tellg();
    if (endPos < 0) {
        setError("Failed to query size of image file: " + filepath_);
        stream_->close();
        stream_.reset();
        return false;
    }

    fileSize_ = static_cast<uint64_t>(endPos);
    totalSectors_ = (fileSize_ + sectorSize_ - 1) / sectorSize_;

    // Reset seek position to start
    stream_->seekg(0, std::ios::beg);
    if (!stream_->good()) {
        setError("Failed to rewind image file stream after size query");
        stream_->close();
        stream_.reset();
        return false;
    }

    return true;
}

void DiskImageReader::close() {
#if defined(_WIN32)
    if (winDeviceHandle_) {
        CloseHandle(reinterpret_cast<HANDLE>(winDeviceHandle_));
        winDeviceHandle_ = nullptr;
    }
#endif
    if (stream_ && stream_->is_open()) {
        stream_->close();
    }
    stream_.reset();
    fileSize_ = 0;
    totalSectors_ = 0;
    currentOffset_ = 0;
    filepath_.clear();
}

bool DiskImageReader::isOpen() const {
    std::lock_guard<std::mutex> lock(ioMutex_);
    return (stream_ && stream_->is_open()) || (winDeviceHandle_ != nullptr);
}

uint64_t DiskImageReader::size() const {
    std::lock_guard<std::mutex> lock(ioMutex_);
    return fileSize_;
}

uint32_t DiskImageReader::sectorSize() const {
    std::lock_guard<std::mutex> lock(ioMutex_);
    return sectorSize_;
}

uint64_t DiskImageReader::totalSectors() const {
    std::lock_guard<std::mutex> lock(ioMutex_);
    return totalSectors_;
}

const std::string& DiskImageReader::filepath() const {
    std::lock_guard<std::mutex> lock(ioMutex_);
    return filepath_;
}

bool DiskImageReader::seek(uint64_t offset) {
    std::lock_guard<std::mutex> lock(ioMutex_);
    clearError();

#if defined(_WIN32)
    if (winDeviceHandle_) {
        if (fileSize_ > 0 && offset > fileSize_) {
            setError("Seek offset out of bounds: requested offset " + std::to_string(offset) +
                     ", total size " + std::to_string(fileSize_));
            return false;
        }
        LARGE_INTEGER li;
        li.QuadPart = static_cast<LONGLONG>(offset);
        if (!SetFilePointerEx(reinterpret_cast<HANDLE>(winDeviceHandle_), li, NULL, FILE_BEGIN)) {
            DWORD dwErr = GetLastError();
            setError("Device seek failed at offset " + std::to_string(offset) + " (Windows Error " + std::to_string(dwErr) + ")");
            return false;
        }
        currentOffset_ = offset;
        return true;
    }
#endif

    if (!stream_ || !stream_->is_open()) {
        setError("Seek failed: no disk image opened");
        return false;
    }

    if (offset > fileSize_) {
        setError("Seek offset out of bounds: requested offset " + std::to_string(offset) +
                 ", total size " + std::to_string(fileSize_));
        return false;
    }

    if (stream_->eof() || stream_->fail()) {
        stream_->clear();
    }

    stream_->seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    if (!stream_->good()) {
        setError("Stream seek operation failed at offset " + std::to_string(offset));
        return false;
    }

    return true;
}

uint64_t DiskImageReader::tell() {
    std::lock_guard<std::mutex> lock(ioMutex_);
#if defined(_WIN32)
    if (winDeviceHandle_) {
        return currentOffset_;
    }
#endif
    if (!stream_ || !stream_->is_open()) {
        return 0;
    }
    std::streamoff pos = stream_->tellg();
    return (pos < 0) ? 0 : static_cast<uint64_t>(pos);
}

bool DiskImageReader::read(uint64_t offset, uint8_t* buffer, size_t size) {
    std::lock_guard<std::mutex> lock(ioMutex_);
    clearError();

#if defined(_WIN32)
    if (winDeviceHandle_) {
        if (!buffer && size > 0) {
            setError("Read failed: destination buffer is null");
            return false;
        }
        if (size == 0) {
            return true;
        }
        if (fileSize_ > 0 && (offset > fileSize_ || (fileSize_ - offset) < size)) {
            setError("Read bounds error: offset " + std::to_string(offset) + " + length " +
                     std::to_string(size) + " exceeds device size " + std::to_string(fileSize_));
            return false;
        }

        uint32_t secSize = sectorSize_ > 0 ? sectorSize_ : 512;
        uint64_t alignedOffset = (offset / secSize) * secSize;
        uint64_t endOffset = offset + size;
        uint64_t alignedEnd = ((endOffset + secSize - 1) / secSize) * secSize;
        uint64_t alignedBytes = alignedEnd - alignedOffset;

        if (offset == alignedOffset && size == alignedBytes) {
            LARGE_INTEGER li;
            li.QuadPart = static_cast<LONGLONG>(alignedOffset);
            if (!SetFilePointerEx(reinterpret_cast<HANDLE>(winDeviceHandle_), li, NULL, FILE_BEGIN)) {
                DWORD dwErr = GetLastError();
                setError("Device seek prior to read failed at offset " + std::to_string(offset) + " (Windows Error " + std::to_string(dwErr) + ")");
                return false;
            }

            DWORD bytesToRead = static_cast<DWORD>(size);
            DWORD bytesRead = 0;
            if (!ReadFile(reinterpret_cast<HANDLE>(winDeviceHandle_), buffer, bytesToRead, &bytesRead, NULL)) {
                DWORD dwErr = GetLastError();
                setError("Device read failed at offset " + std::to_string(offset) + " (Windows Error " + std::to_string(dwErr) + ")");
                return false;
            }

            currentOffset_ = offset + bytesRead;

            if (bytesRead != bytesToRead) {
                setError("Short read encountered: requested " + std::to_string(size) +
                         " bytes, but only read " + std::to_string(bytesRead) + " bytes");
                return false;
            }
            return true;
        } else {
            LARGE_INTEGER li;
            li.QuadPart = static_cast<LONGLONG>(alignedOffset);
            if (!SetFilePointerEx(reinterpret_cast<HANDLE>(winDeviceHandle_), li, NULL, FILE_BEGIN)) {
                DWORD dwErr = GetLastError();
                setError("Device seek prior to read failed at aligned offset " + std::to_string(alignedOffset) + " (Windows Error " + std::to_string(dwErr) + ")");
                return false;
            }

            std::vector<uint8_t> bounceBuffer(alignedBytes);
            DWORD bytesToRead = static_cast<DWORD>(alignedBytes);
            DWORD bytesRead = 0;
            if (!ReadFile(reinterpret_cast<HANDLE>(winDeviceHandle_), bounceBuffer.data(), bytesToRead, &bytesRead, NULL)) {
                DWORD dwErr = GetLastError();
                setError("Device read failed at aligned offset " + std::to_string(alignedOffset) + " (Windows Error " + std::to_string(dwErr) + ")");
                return false;
            }

            size_t leadOffset = static_cast<size_t>(offset - alignedOffset);
            if (bytesRead <= leadOffset) {
                setError("Device short read: target byte offset unreachable in sector chunk");
                return false;
            }

            size_t available = bytesRead - leadOffset;
            size_t copyBytes = std::min(size, available);
            std::memcpy(buffer, bounceBuffer.data() + leadOffset, copyBytes);
            currentOffset_ = offset + copyBytes;

            if (copyBytes < size) {
                setError("Short read encountered: requested " + std::to_string(size) +
                         " bytes, but only read " + std::to_string(copyBytes) + " bytes");
                return false;
            }
            return true;
        }
    }
#endif

    if (!stream_ || !stream_->is_open()) {
        setError("Read failed: no disk image opened");
        return false;
    }

    if (!buffer && size > 0) {
        setError("Read failed: destination buffer is null");
        return false;
    }

    if (size == 0) {
        return true;
    }

    // Bounds check and overflow check
    if (offset > fileSize_ || (fileSize_ - offset) < size) {
        setError("Read bounds error: offset " + std::to_string(offset) + " + length " +
                 std::to_string(size) + " exceeds image size " + std::to_string(fileSize_));
        return false;
    }

    if (stream_->eof() || stream_->fail()) {
        stream_->clear();
    }

    stream_->seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    if (!stream_->good()) {
        setError("Seek prior to read failed at offset " + std::to_string(offset));
        return false;
    }

    stream_->read(reinterpret_cast<char*>(buffer), static_cast<std::streamsize>(size));
    std::streamsize bytesRead = stream_->gcount();

    if (bytesRead != static_cast<std::streamsize>(size)) {
        setError("Short read encountered: requested " + std::to_string(size) +
                 " bytes, but only read " + std::to_string(bytesRead) + " bytes");
        return false;
    }

    return true;
}

std::vector<uint8_t> DiskImageReader::readBytes(uint64_t offset, size_t size) {
    std::vector<uint8_t> buffer(size);
    if (read(offset, buffer.data(), size)) {
        return buffer;
    }
    return {};
}

std::vector<uint8_t> DiskImageReader::readSector(uint64_t sectorNumber) {
    std::vector<uint8_t> buffer(sectorSize_);
    if (readSector(sectorNumber, buffer.data())) {
        return buffer;
    }
    return {};
}

bool DiskImageReader::readSector(uint64_t sectorNumber, uint8_t* outBuffer) {
    return readSectors(sectorNumber, 1, outBuffer);
}

bool DiskImageReader::readSectors(uint64_t startSector, uint64_t count, uint8_t* outBuffer) {
    if (count == 0) {
        return true;
    }

    uint64_t byteOffset = startSector * sectorSize_;
    uint64_t totalBytes = count * sectorSize_;

    return read(byteOffset, outBuffer, static_cast<size_t>(totalBytes));
}

const std::string& DiskImageReader::lastError() const {
    return lastError_;
}

uint32_t DiskImageReader::lastErrorCode() const {
    return lastErrorCode_;
}

void DiskImageReader::setError(const std::string& errorMsg) const {
    lastError_ = errorMsg;
}

void DiskImageReader::setErrorWithCode(const std::string& errorMsg, uint32_t errorCode) const {
    lastError_ = errorMsg;
    lastErrorCode_ = errorCode;
}

void DiskImageReader::clearError() const {
    lastError_.clear();
    lastErrorCode_ = 0;
}

} // namespace forensivault::core
