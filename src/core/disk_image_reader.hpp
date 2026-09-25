#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <fstream>
#include <memory>
#include <mutex>

namespace forensivault::core {

/**
 * @brief Strictly read-only raw disk image (.dd, .img, .bin) reader.
 * Emulates a hardware write-blocker by ensuring no write access is ever requested,
 * preventing any alteration of evidence images.
 */
class DiskImageReader {
public:
    static constexpr uint32_t DEFAULT_SECTOR_SIZE = 512;

    DiskImageReader();
    explicit DiskImageReader(const std::string& filepath, uint32_t sectorSize = DEFAULT_SECTOR_SIZE);
    ~DiskImageReader();

    // Non-copyable to ensure unique handle ownership
    DiskImageReader(const DiskImageReader&) = delete;
    DiskImageReader& operator=(const DiskImageReader&) = delete;

    // Moveable
    DiskImageReader(DiskImageReader&& other) noexcept;
    DiskImageReader& operator=(DiskImageReader&& other) noexcept;

    /**
     * @brief Open a disk image file in binary read-only mode.
     * @param filepath Path to the image file (.img, .dd, .raw).
     * @param sectorSize Sector size in bytes (defaults to 512).
     * @return true if opened successfully, false on error.
     */
    bool open(const std::string& filepath, uint32_t sectorSize = DEFAULT_SECTOR_SIZE);

    /**
     * @brief Close the disk image file and release resources.
     */
    void close();

    /**
     * @brief Check if a valid disk image is currently open.
     */
    [[nodiscard]] bool isOpen() const;

    /**
     * @brief Get total image size in bytes.
     */
    [[nodiscard]] uint64_t size() const;

    /**
     * @brief Get the configured sector size in bytes.
     */
    [[nodiscard]] uint32_t sectorSize() const;

    /**
     * @brief Get the total number of sectors in the image.
     */
    [[nodiscard]] uint64_t totalSectors() const;

    /**
     * @brief Get the path of the currently opened file.
     */
    [[nodiscard]] const std::string& filepath() const;

    /**
     * @brief Seek internal read position to a specific byte offset.
     * @param offset Absolute byte offset from the start of the image.
     * @return true if seek was successful and within bounds.
     */
    bool seek(uint64_t offset);

    /**
     * @brief Current read cursor offset in bytes.
     */
    [[nodiscard]] uint64_t tell();

    /**
     * @brief Read arbitrary byte range into a caller-allocated buffer.
     * @param offset Absolute byte offset in the image.
     * @param buffer Pointer to destination memory buffer.
     * @param size Number of bytes to read.
     * @return true if exactly `size` bytes were read successfully, false on bounds or I/O error.
     */
    bool read(uint64_t offset, uint8_t* buffer, size_t size);

    /**
     * @brief Read arbitrary byte range into a newly allocated vector.
     * @param offset Absolute byte offset in the image.
     * @param size Number of bytes to read.
     * @return std::vector<uint8_t> containing the bytes, or empty on failure.
     */
    std::vector<uint8_t> readBytes(uint64_t offset, size_t size);

    /**
     * @brief Read a single sector by its sector index.
     * @param sectorNumber 0-indexed sector number.
     * @return std::vector<uint8_t> containing sector data (length = sectorSize()), empty on failure.
     */
    std::vector<uint8_t> readSector(uint64_t sectorNumber);

    /**
     * @brief Read a single sector into a caller-allocated buffer (must be at least sectorSize() bytes).
     * @param sectorNumber 0-indexed sector number.
     * @param outBuffer Destination buffer.
     * @return true if sector read succeeded.
     */
    bool readSector(uint64_t sectorNumber, uint8_t* outBuffer);

    /**
     * @brief Read multiple contiguous sectors into a caller-allocated buffer.
     * @param startSector Starting 0-indexed sector number.
     * @param count Number of sectors to read.
     * @param outBuffer Destination buffer (must be at least count * sectorSize() bytes).
     * @return true if all sectors were read successfully.
     */
    bool readSectors(uint64_t startSector, uint64_t count, uint8_t* outBuffer);

    /**
     * @brief Retrieve the last error message, if any.
     */
    [[nodiscard]] const std::string& lastError() const;

    /**
     * @brief Retrieve the last native system error code (e.g. 5 for ERROR_ACCESS_DENIED).
     */
    [[nodiscard]] uint32_t lastErrorCode() const;

private:
    void setError(const std::string& errorMsg) const;
    void setErrorWithCode(const std::string& errorMsg, uint32_t errorCode) const;
    void clearError() const;

    std::string filepath_;
    uint32_t sectorSize_{DEFAULT_SECTOR_SIZE};
    uint64_t fileSize_{0};
    uint64_t totalSectors_{0};
    std::unique_ptr<std::ifstream> stream_;
    void* winDeviceHandle_{nullptr};
    uint64_t currentOffset_{0};
    mutable std::string lastError_;
    mutable uint32_t lastErrorCode_{0};
    mutable std::mutex ioMutex_;
};

} // namespace forensivault::core
