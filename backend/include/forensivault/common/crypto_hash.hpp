#pragma once

#include "forensivault/common/types.hpp"
#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>

namespace forensivault {

class CryptoHash {
public:
    // Computes lowercase hex-encoded SHA-256 of a byte buffer
    static std::string sha256(const uint8_t* data, size_t length);
    static std::string sha256(const ByteBuffer& buffer);
    static std::string sha256(const std::string& text);

    // Computes lowercase hex-encoded MD5 of a byte buffer
    static std::string md5(const uint8_t* data, size_t length);
    static std::string md5(const ByteBuffer& buffer);
    static std::string md5(const std::string& text);

    // Computes standard IEEE 802.3 CRC32
    static uint32_t crc32(const uint8_t* data, size_t length, uint32_t initialCrc = 0);
    static uint32_t crc32(const ByteBuffer& buffer, uint32_t initialCrc = 0);

    // Computes Shannon Entropy (0.0 to 8.0 bits per byte)
    // 0.0 indicates completely uniform data (e.g. all 0x00)
    // ~8.0 indicates high randomness (encrypted or compressed data, or random wipe pass)
    static double calculateEntropy(const uint8_t* data, size_t length);
    static double calculateEntropy(const ByteBuffer& buffer);

    // Incremental SHA-256 context for streaming large files or disk images
    class Sha256Context {
    public:
        Sha256Context();
        void update(const uint8_t* data, size_t length);
        void update(const ByteBuffer& buffer);
        std::string finalize();

    private:
        uint32_t state[8];
        uint64_t count;
        uint8_t buffer[64];
        void transform(const uint8_t block[64]);
    };

    // Incremental MD5 context for streaming
    class Md5Context {
    public:
        Md5Context();
        void update(const uint8_t* data, size_t length);
        void update(const ByteBuffer& buffer);
        std::string finalize();

    private:
        uint32_t state[4];
        uint64_t count;
        uint8_t buffer[64];
        void transform(const uint8_t block[64]);
    };
};

} // namespace forensivault
