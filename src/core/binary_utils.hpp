#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>
#include <optional>

namespace forensivault::core {

/**
 * @brief High-performance binary analysis utilities for forensic data inspection.
 */
class BinaryUtils {
public:
    // ---------------- Hexadecimal Formatting ----------------
    
    /**
     * @brief Converts a single byte to a 2-character hex string (e.g. "0A", "FF").
     */
    static std::string byteToHex(uint8_t byte, bool uppercase = true);

    /**
     * @brief Converts byte buffer to delimited hex string.
     */
    static std::string toHex(const uint8_t* data, size_t length, 
                             const std::string& delimiter = " ", bool uppercase = true);
    static std::string toHex(const std::vector<uint8_t>& data, 
                             const std::string& delimiter = " ", bool uppercase = true);

    /**
     * @brief Parses a hex string (with or without spaces/delimiters) into raw bytes.
     */
    static std::vector<uint8_t> fromHex(const std::string& hexString);

    // ---------------- Binary (Bitwise) Representation ----------------
    
    /**
     * @brief Converts a single byte to an 8-character binary string (e.g. "11110000").
     */
    static std::string byteToBinary(uint8_t byte);

    /**
     * @brief Converts byte sequence to binary bitwise representation.
     */
    static std::string toBinary(const uint8_t* data, size_t length, const std::string& delimiter = " ");
    static std::string toBinary(const std::vector<uint8_t>& data, const std::string& delimiter = " ");

    // ---------------- ASCII Representation ----------------
    
    /**
     * @brief Converts a byte to printable ASCII char or substitute dot '.'.
     */
    static char toAscii(uint8_t byte, char nonPrintable = '.');

    /**
     * @brief Converts buffer to printable ASCII string.
     */
    static std::string toAsciiString(const uint8_t* data, size_t length, char nonPrintable = '.');

    // ---------------- Forensic Hex Dump Formatting ----------------
    
    /**
     * @brief Generates forensic hex dump matching standard analyst tooling:
     * OFFSET        HEX BYTES                                         ASCII
     * 00000000      FF D8 FF E0 00 10 4A 46  49 46 00 01 01 01 00 60  ......JFIF.....`
     */
    static std::string formatHexDump(const uint8_t* data, size_t length, 
                                     uint64_t baseOffset = 0, size_t bytesPerLine = 16);
    static std::string formatHexDump(const std::vector<uint8_t>& data, 
                                     uint64_t baseOffset = 0, size_t bytesPerLine = 16);

    // ---------------- Byte Searching ----------------
    
    /**
     * @brief Find first occurrence of a needle in a haystack using Boyer-Moore-Horspool.
     * @return Offset of first match, or -1 if not found.
     */
    static int64_t findFirst(const uint8_t* haystack, size_t haystackLen, 
                             const uint8_t* needle, size_t needleLen);
    static int64_t findFirst(const std::vector<uint8_t>& haystack, 
                             const std::vector<uint8_t>& needle);

    /**
     * @brief Find all occurrences of needle within haystack.
     * @return Vector of matching offsets.
     */
    static std::vector<uint64_t> findAll(const uint8_t* haystack, size_t haystackLen, 
                                         const uint8_t* needle, size_t needleLen);
    static std::vector<uint64_t> findAll(const std::vector<uint8_t>& haystack, 
                                         const std::vector<uint8_t>& needle);

    // ---------------- Signature Comparison ----------------
    
    /**
     * @brief Compares data starting at offset 0 against a fixed byte signature.
     */
    static bool matchesSignature(const uint8_t* data, size_t dataLen, 
                                 const uint8_t* signature, size_t sigLen);
    static bool matchesSignature(const std::vector<uint8_t>& data, 
                                 const std::vector<uint8_t>& signature);

    /**
     * @brief Compares data against a signature with wildcards / mask.
     * Where mask[i] == 0xFF, data[i] must equal signature[i]. Where mask[i] == 0x00, byte is ignored.
     */
    static bool matchesMaskedSignature(const uint8_t* data, size_t dataLen,
                                       const uint8_t* signature, const uint8_t* mask, size_t sigLen);

    // ---------------- Offset & Sector Calculations ----------------
    
    /**
     * @brief Converts a 0-indexed sector number to its absolute byte offset.
     */
    static constexpr uint64_t sectorToByteOffset(uint64_t sectorNumber, uint32_t sectorSize = 512) {
        return sectorNumber * static_cast<uint64_t>(sectorSize);
    }

    /**
     * @brief Converts an absolute byte offset to the containing sector number.
     */
    static constexpr uint64_t byteToSector(uint64_t byteOffset, uint32_t sectorSize = 512) {
        return (sectorSize == 0) ? 0 : (byteOffset / static_cast<uint64_t>(sectorSize));
    }

    /**
     * @brief Calculates remainder offset within containing sector.
     */
    static constexpr uint32_t offsetWithinSector(uint64_t byteOffset, uint32_t sectorSize = 512) {
        return (sectorSize == 0) ? 0 : static_cast<uint32_t>(byteOffset % static_cast<uint64_t>(sectorSize));
    }

    /**
     * @brief Aligns byte offset down to the nearest sector boundary.
     */
    static constexpr uint64_t alignToSector(uint64_t byteOffset, uint32_t sectorSize = 512) {
        return (sectorSize == 0) ? byteOffset : (byteOffset - (byteOffset % static_cast<uint64_t>(sectorSize)));
    }

    /**
     * @brief Calculates total number of sectors spanned by a byte range.
     */
    static uint64_t calculateSectorSpan(uint64_t startByte, uint64_t lengthBytes, uint32_t sectorSize = 512);

    // ---------------- SHA-256 Hashing ----------------
    
    /**
     * @brief Calculates standard SHA-256 hex string.
     */
    static std::string sha256(const uint8_t* data, size_t length);
    static std::string sha256(const std::vector<uint8_t>& data);
};

} // namespace forensivault::core
