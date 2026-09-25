#include "core/binary_utils.hpp"
#include "forensivault/common/crypto_hash.hpp"
#include <iomanip>
#include <sstream>
#include <cstring>
#include <cctype>
#include <array>

namespace forensivault::core {

namespace {

constexpr char HEX_CHARS_UPPER[] = "0123456789ABCDEF";
constexpr char HEX_CHARS_LOWER[] = "0123456789abcdef";

inline int hexCharToInt(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

} // anonymous namespace

// ---------------- Hexadecimal Formatting ----------------

std::string BinaryUtils::byteToHex(uint8_t byte, bool uppercase) {
    const char* lut = uppercase ? HEX_CHARS_UPPER : HEX_CHARS_LOWER;
    std::string s(2, '0');
    s[0] = lut[(byte >> 4) & 0x0F];
    s[1] = lut[byte & 0x0F];
    return s;
}

std::string BinaryUtils::toHex(const uint8_t* data, size_t length, 
                             const std::string& delimiter, bool uppercase) {
    if (!data || length == 0) return "";

    std::string result;
    result.reserve(length * (2 + delimiter.size()));

    for (size_t i = 0; i < length; ++i) {
        if (i > 0 && !delimiter.empty()) {
            result += delimiter;
        }
        result += byteToHex(data[i], uppercase);
    }
    return result;
}

std::string BinaryUtils::toHex(const std::vector<uint8_t>& data, 
                             const std::string& delimiter, bool uppercase) {
    return toHex(data.data(), data.size(), delimiter, uppercase);
}

std::vector<uint8_t> BinaryUtils::fromHex(const std::string& hexString) {
    std::vector<uint8_t> bytes;
    int highNibble = -1;

    for (char c : hexString) {
        if (std::isspace(static_cast<unsigned char>(c)) || c == ':' || c == '-') {
            continue;
        }

        int val = hexCharToInt(c);
        if (val < 0) continue;

        if (highNibble < 0) {
            highNibble = val;
        } else {
            bytes.push_back(static_cast<uint8_t>((highNibble << 4) | val));
            highNibble = -1;
        }
    }
    return bytes;
}

// ---------------- Binary (Bitwise) Representation ----------------

std::string BinaryUtils::byteToBinary(uint8_t byte) {
    std::string s(8, '0');
    for (int i = 7; i >= 0; --i) {
        s[7 - i] = ((byte >> i) & 1) ? '1' : '0';
    }
    return s;
}

std::string BinaryUtils::toBinary(const uint8_t* data, size_t length, const std::string& delimiter) {
    if (!data || length == 0) return "";

    std::string result;
    result.reserve(length * (8 + delimiter.size()));

    for (size_t i = 0; i < length; ++i) {
        if (i > 0 && !delimiter.empty()) {
            result += delimiter;
        }
        result += byteToBinary(data[i]);
    }
    return result;
}

std::string BinaryUtils::toBinary(const std::vector<uint8_t>& data, const std::string& delimiter) {
    return toBinary(data.data(), data.size(), delimiter);
}

// ---------------- ASCII Representation ----------------

char BinaryUtils::toAscii(uint8_t byte, char nonPrintable) {
    return (byte >= 32 && byte <= 126) ? static_cast<char>(byte) : nonPrintable;
}

std::string BinaryUtils::toAsciiString(const uint8_t* data, size_t length, char nonPrintable) {
    if (!data || length == 0) return "";
    std::string result(length, nonPrintable);
    for (size_t i = 0; i < length; ++i) {
        result[i] = toAscii(data[i], nonPrintable);
    }
    return result;
}

// ---------------- Forensic Hex Dump Formatting ----------------

std::string BinaryUtils::formatHexDump(const uint8_t* data, size_t length, 
                                     uint64_t baseOffset, size_t bytesPerLine) {
    if (!data || length == 0) return "";
    if (bytesPerLine == 0) bytesPerLine = 16;

    std::ostringstream ss;
    ss << "OFFSET        HEX BYTES                                         ASCII\n";

    for (size_t i = 0; i < length; i += bytesPerLine) {
        size_t chunk = std::min(bytesPerLine, length - i);

        // Print offset (8-digit hex)
        ss << std::hex << std::uppercase << std::setfill('0') << std::setw(8) 
           << (baseOffset + i) << "      ";

        // Print hex bytes
        for (size_t j = 0; j < bytesPerLine; ++j) {
            if (j < chunk) {
                ss << byteToHex(data[i + j], true) << " ";
            } else {
                ss << "   ";
            }
            if (j == 7) {
                ss << " ";
            }
        }

        ss << " ";

        // Print ASCII characters
        for (size_t j = 0; j < chunk; ++j) {
            ss << toAscii(data[i + j]);
        }

        ss << "\n";
    }

    return ss.str();
}

std::string BinaryUtils::formatHexDump(const std::vector<uint8_t>& data, 
                                     uint64_t baseOffset, size_t bytesPerLine) {
    return formatHexDump(data.data(), data.size(), baseOffset, bytesPerLine);
}

// ---------------- Byte Searching (Boyer-Moore-Horspool) ----------------

int64_t BinaryUtils::findFirst(const uint8_t* haystack, size_t haystackLen, 
                             const uint8_t* needle, size_t needleLen) {
    if (!haystack || !needle || needleLen == 0 || haystackLen < needleLen) {
        return -1;
    }

    if (needleLen == 1) {
        const void* found = std::memchr(haystack, needle[0], haystackLen);
        if (found) {
            return static_cast<int64_t>(static_cast<const uint8_t*>(found) - haystack);
        }
        return -1;
    }

    // Build bad character shift table
    std::array<size_t, 256> shiftTable;
    shiftTable.fill(needleLen);
    for (size_t i = 0; i < needleLen - 1; ++i) {
        shiftTable[needle[i]] = needleLen - 1 - i;
    }

    size_t k = needleLen - 1;
    while (k < haystackLen) {
        size_t i = needleLen - 1;
        size_t j = k;

        while (haystack[j] == needle[i]) {
            if (i == 0) {
                return static_cast<int64_t>(j);
            }
            --i;
            --j;
        }

        k += shiftTable[haystack[k]];
    }

    return -1;
}

int64_t BinaryUtils::findFirst(const std::vector<uint8_t>& haystack, 
                             const std::vector<uint8_t>& needle) {
    return findFirst(haystack.data(), haystack.size(), needle.data(), needle.size());
}

std::vector<uint64_t> BinaryUtils::findAll(const uint8_t* haystack, size_t haystackLen, 
                                         const uint8_t* needle, size_t needleLen) {
    std::vector<uint64_t> matches;
    if (!haystack || !needle || needleLen == 0 || haystackLen < needleLen) {
        return matches;
    }

    uint64_t currentOffset = 0;
    while (currentOffset + needleLen <= haystackLen) {
        int64_t pos = findFirst(haystack + currentOffset, haystackLen - currentOffset, 
                                needle, needleLen);
        if (pos < 0) {
            break;
        }

        matches.push_back(currentOffset + static_cast<uint64_t>(pos));
        currentOffset += static_cast<uint64_t>(pos) + 1;
    }

    return matches;
}

std::vector<uint64_t> BinaryUtils::findAll(const std::vector<uint8_t>& haystack, 
                                         const std::vector<uint8_t>& needle) {
    return findAll(haystack.data(), haystack.size(), needle.data(), needle.size());
}

// ---------------- Signature Comparison ----------------

bool BinaryUtils::matchesSignature(const uint8_t* data, size_t dataLen, 
                                 const uint8_t* signature, size_t sigLen) {
    if (!data || !signature || dataLen < sigLen) {
        return false;
    }
    return std::memcmp(data, signature, sigLen) == 0;
}

bool BinaryUtils::matchesSignature(const std::vector<uint8_t>& data, 
                                 const std::vector<uint8_t>& signature) {
    return matchesSignature(data.data(), data.size(), signature.data(), signature.size());
}

bool BinaryUtils::matchesMaskedSignature(const uint8_t* data, size_t dataLen,
                                       const uint8_t* signature, const uint8_t* mask, size_t sigLen) {
    if (!data || !signature || !mask || dataLen < sigLen) {
        return false;
    }

    for (size_t i = 0; i < sigLen; ++i) {
        if ((data[i] & mask[i]) != (signature[i] & mask[i])) {
            return false;
        }
    }
    return true;
}

// ---------------- Offset Calculations ----------------

uint64_t BinaryUtils::calculateSectorSpan(uint64_t startByte, uint64_t lengthBytes, uint32_t sectorSize) {
    if (lengthBytes == 0 || sectorSize == 0) return 0;

    uint64_t startSector = byteToSector(startByte, sectorSize);
    uint64_t endSector = byteToSector(startByte + lengthBytes - 1, sectorSize);

    return (endSector - startSector) + 1;
}

// ---------------- SHA-256 Hashing ----------------

std::string BinaryUtils::sha256(const uint8_t* data, size_t length) {
    return CryptoHash::sha256(data, length);
}

std::string BinaryUtils::sha256(const std::vector<uint8_t>& data) {
    return CryptoHash::sha256(data);
}

} // namespace forensivault::core
