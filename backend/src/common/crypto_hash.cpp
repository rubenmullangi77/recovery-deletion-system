#include "forensivault/common/crypto_hash.hpp"
#include <iomanip>
#include <sstream>
#include <cmath>
#include <cstring>
#include <array>

namespace forensivault {

namespace {

inline uint32_t rotr32(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

inline uint32_t rotl32(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32 - n));
}

// SHA-256 Constants
constexpr uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

} // anonymous namespace

// ---------------- SHA-256 Implementation ----------------

CryptoHash::Sha256Context::Sha256Context() {
    state[0] = 0x6a09e667;
    state[1] = 0xbb67ae85;
    state[2] = 0x3c6ef372;
    state[3] = 0xa54ff53a;
    state[4] = 0x510e527f;
    state[5] = 0x9b05688c;
    state[6] = 0x1f83d9ab;
    state[7] = 0x5be0cd19;
    count = 0;
    std::memset(buffer, 0, sizeof(buffer));
}

void CryptoHash::Sha256Context::transform(const uint8_t block[64]) {
    uint32_t w[64];
    for (size_t i = 0; i < 16; ++i) {
        w[i] = (static_cast<uint32_t>(block[i * 4]) << 24) |
               (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
               (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
               (static_cast<uint32_t>(block[i * 4 + 3]));
    }

    for (size_t i = 16; i < 64; ++i) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

    for (size_t i = 0; i < 64; ++i) {
        uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + s1 + ch + K256[i] + w[i];
        uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void CryptoHash::Sha256Context::update(const uint8_t* data, size_t length) {
    size_t bufferIdx = static_cast<size_t>(count % 64);
    count += length;

    size_t i = 0;
    if (bufferIdx > 0) {
        size_t needed = 64 - bufferIdx;
        if (length < needed) {
            std::memcpy(buffer + bufferIdx, data, length);
            return;
        }
        std::memcpy(buffer + bufferIdx, data, needed);
        transform(buffer);
        i = needed;
    }

    for (; i + 64 <= length; i += 64) {
        transform(data + i);
    }

    if (i < length) {
        std::memcpy(buffer, data + i, length - i);
    }
}

void CryptoHash::Sha256Context::update(const ByteBuffer& buffer) {
    update(buffer.data(), buffer.size());
}

std::string CryptoHash::Sha256Context::finalize() {
    uint8_t finalBuffer[64];
    size_t bufferIdx = static_cast<size_t>(count % 64);
    std::memcpy(finalBuffer, buffer, bufferIdx);

    finalBuffer[bufferIdx++] = 0x80;
    if (bufferIdx > 56) {
        std::memset(finalBuffer + bufferIdx, 0, 64 - bufferIdx);
        transform(finalBuffer);
        std::memset(finalBuffer, 0, 56);
    } else {
        std::memset(finalBuffer + bufferIdx, 0, 56 - bufferIdx);
    }

    uint64_t totalBits = count * 8;
    for (int i = 7; i >= 0; --i) {
        finalBuffer[56 + (7 - i)] = static_cast<uint8_t>((totalBits >> (i * 8)) & 0xFF);
    }
    transform(finalBuffer);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < 8; ++i) {
        oss << std::setw(8) << state[i];
    }
    return oss.str();
}

std::string CryptoHash::sha256(const uint8_t* data, size_t length) {
    Sha256Context ctx;
    ctx.update(data, length);
    return ctx.finalize();
}

std::string CryptoHash::sha256(const ByteBuffer& buffer) {
    return sha256(buffer.data(), buffer.size());
}

std::string CryptoHash::sha256(const std::string& text) {
    return sha256(reinterpret_cast<const uint8_t*>(text.data()), text.size());
}

// ---------------- MD5 Implementation ----------------

namespace {

constexpr uint32_t S11 = 7, S12 = 12, S13 = 17, S14 = 22;
constexpr uint32_t S21 = 5, S22 = 9,  S23 = 14, S24 = 20;
constexpr uint32_t S31 = 4, S32 = 11, S33 = 16, S34 = 23;
constexpr uint32_t S41 = 6, S42 = 10, S43 = 15, S44 = 21;

inline uint32_t F(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); }
inline uint32_t G(uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & ~z); }
inline uint32_t H(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
inline uint32_t I(uint32_t x, uint32_t y, uint32_t z) { return y ^ (x | ~z); }

inline void FF(uint32_t& a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac) {
    a = rotl32(a + F(b, c, d) + x + ac, s) + b;
}
inline void GG(uint32_t& a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac) {
    a = rotl32(a + G(b, c, d) + x + ac, s) + b;
}
inline void HH(uint32_t& a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac) {
    a = rotl32(a + H(b, c, d) + x + ac, s) + b;
}
inline void II(uint32_t& a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac) {
    a = rotl32(a + I(b, c, d) + x + ac, s) + b;
}

} // anonymous namespace

CryptoHash::Md5Context::Md5Context() {
    state[0] = 0x67452301;
    state[1] = 0xefcdab89;
    state[2] = 0x98badcfe;
    state[3] = 0x10325476;
    count = 0;
    std::memset(buffer, 0, sizeof(buffer));
}

void CryptoHash::Md5Context::transform(const uint8_t block[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t x[16];

    for (size_t i = 0; i < 16; ++i) {
        x[i] = static_cast<uint32_t>(block[i * 4]) |
               (static_cast<uint32_t>(block[i * 4 + 1]) << 8) |
               (static_cast<uint32_t>(block[i * 4 + 2]) << 16) |
               (static_cast<uint32_t>(block[i * 4 + 3]) << 24);
    }

    // Round 1
    FF(a, b, c, d, x[ 0], S11, 0xd76aa478);
    FF(d, a, b, c, x[ 1], S12, 0xe8c7b756);
    FF(c, d, a, b, x[ 2], S13, 0x242070db);
    FF(b, c, d, a, x[ 3], S14, 0xc1bdceee);
    FF(a, b, c, d, x[ 4], S11, 0xf57c0faf);
    FF(d, a, b, c, x[ 5], S12, 0x4787c62a);
    FF(c, d, a, b, x[ 6], S13, 0xa8304613);
    FF(b, c, d, a, x[ 7], S14, 0xfd469501);
    FF(a, b, c, d, x[ 8], S11, 0x698098d8);
    FF(d, a, b, c, x[ 9], S12, 0x8b44f7af);
    FF(c, d, a, b, x[10], S13, 0xffff5bb1);
    FF(b, c, d, a, x[11], S14, 0x895cd7be);
    FF(a, b, c, d, x[12], S11, 0x6b901122);
    FF(d, a, b, c, x[13], S12, 0xfd987193);
    FF(c, d, a, b, x[14], S13, 0xa679438e);
    FF(b, c, d, a, x[15], S14, 0x49b40821);

    // Round 2
    GG(a, b, c, d, x[ 1], S21, 0xf61e2562);
    GG(d, a, b, c, x[ 6], S22, 0xc040b340);
    GG(c, d, a, b, x[11], S23, 0x265e5a51);
    GG(b, c, d, a, x[ 0], S24, 0xe9b6c7aa);
    GG(a, b, c, d, x[ 5], S21, 0xd62f105d);
    GG(d, a, b, c, x[10], S22, 0x02441453);
    GG(c, d, a, b, x[15], S23, 0xd8a1e681);
    GG(b, c, d, a, x[ 4], S24, 0xe7d3fbc8);
    GG(a, b, c, d, x[ 9], S21, 0x21e1cde6);
    GG(d, a, b, c, x[14], S22, 0xc33707d6);
    GG(c, d, a, b, x[ 3], S23, 0xf4d50d87);
    GG(b, c, d, a, x[ 8], S24, 0x455a14ed);
    GG(a, b, c, d, x[13], S21, 0xa9e3e905);
    GG(d, a, b, c, x[ 2], S22, 0xfcefa3f8);
    GG(c, d, a, b, x[ 7], S23, 0x676f02d9);
    GG(b, c, d, a, x[12], S24, 0x8d2a4c8a);

    // Round 3
    HH(a, b, c, d, x[ 5], S31, 0xfffa3942);
    HH(d, a, b, c, x[ 8], S32, 0x8771f681);
    HH(c, d, a, b, x[11], S33, 0x6d9d6122);
    HH(b, c, d, a, x[14], S34, 0xfde5380c);
    HH(a, b, c, d, x[ 1], S31, 0xa4beea44);
    HH(d, a, b, c, x[ 4], S32, 0x4bdecfa9);
    HH(c, d, a, b, x[ 7], S33, 0xf6bb4b60);
    HH(b, c, d, a, x[10], S34, 0xbebfbc70);
    HH(a, b, c, d, x[13], S31, 0x289b7ec6);
    HH(d, a, b, c, x[ 0], S32, 0xeaa127fa);
    HH(c, d, a, b, x[ 3], S33, 0xd4ef3085);
    HH(b, c, d, a, x[ 6], S34, 0x04881d05);
    HH(a, b, c, d, x[ 9], S31, 0xd9d4d039);
    HH(d, a, b, c, x[12], S32, 0xe6db99e5);
    HH(c, d, a, b, x[15], S33, 0x1fa27cf8);
    HH(b, c, d, a, x[ 2], S34, 0xc4ac5665);

    // Round 4
    II(a, b, c, d, x[ 0], S41, 0xf4292244);
    II(d, a, b, c, x[ 7], S42, 0x432aff97);
    II(c, d, a, b, x[14], S43, 0xab9423a7);
    II(b, c, d, a, x[ 5], S44, 0xfc93a039);
    II(a, b, c, d, x[12], S41, 0x655b59c3);
    II(d, a, b, c, x[ 3], S42, 0x8f0ccc92);
    II(c, d, a, b, x[10], S43, 0xffeff47d);
    II(b, c, d, a, x[ 1], S44, 0x85845dd1);
    II(a, b, c, d, x[ 8], S41, 0x6fa87e4f);
    II(d, a, b, c, x[15], S42, 0xfe2ce6e0);
    II(c, d, a, b, x[ 6], S43, 0xa3014314);
    II(b, c, d, a, x[13], S44, 0x4e0811a1);
    II(a, b, c, d, x[ 4], S41, 0xf7537e82);
    II(d, a, b, c, x[11], S42, 0xbd3af235);
    II(c, d, a, b, x[ 2], S43, 0x2ad7d2bb);
    II(b, c, d, a, x[ 9], S44, 0xeb86d391);

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

void CryptoHash::Md5Context::update(const uint8_t* data, size_t length) {
    size_t bufferIdx = static_cast<size_t>(count % 64);
    count += length;

    size_t i = 0;
    if (bufferIdx > 0) {
        size_t needed = 64 - bufferIdx;
        if (length < needed) {
            std::memcpy(buffer + bufferIdx, data, length);
            return;
        }
        std::memcpy(buffer + bufferIdx, data, needed);
        transform(buffer);
        i = needed;
    }

    for (; i + 64 <= length; i += 64) {
        transform(data + i);
    }

    if (i < length) {
        std::memcpy(buffer, data + i, length - i);
    }
}

void CryptoHash::Md5Context::update(const ByteBuffer& buffer) {
    update(buffer.data(), buffer.size());
}

std::string CryptoHash::Md5Context::finalize() {
    uint8_t finalBuffer[64];
    size_t bufferIdx = static_cast<size_t>(count % 64);
    std::memcpy(finalBuffer, buffer, bufferIdx);

    finalBuffer[bufferIdx++] = 0x80;
    if (bufferIdx > 56) {
        std::memset(finalBuffer + bufferIdx, 0, 64 - bufferIdx);
        transform(finalBuffer);
        std::memset(finalBuffer, 0, 56);
    } else {
        std::memset(finalBuffer + bufferIdx, 0, 56 - bufferIdx);
    }

    uint64_t totalBits = count * 8;
    for (size_t i = 0; i < 8; ++i) {
        finalBuffer[56 + i] = static_cast<uint8_t>((totalBits >> (i * 8)) & 0xFF);
    }
    transform(finalBuffer);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < 4; ++i) {
        uint32_t val = state[i];
        oss << std::setw(2) << (val & 0xFF)
            << std::setw(2) << ((val >> 8) & 0xFF)
            << std::setw(2) << ((val >> 16) & 0xFF)
            << std::setw(2) << ((val >> 24) & 0xFF);
    }
    return oss.str();
}

std::string CryptoHash::md5(const uint8_t* data, size_t length) {
    Md5Context ctx;
    ctx.update(data, length);
    return ctx.finalize();
}

std::string CryptoHash::md5(const ByteBuffer& buffer) {
    return md5(buffer.data(), buffer.size());
}

std::string CryptoHash::md5(const std::string& text) {
    return md5(reinterpret_cast<const uint8_t*>(text.data()), text.size());
}

// ---------------- CRC-32 Implementation ----------------

namespace {

const std::array<uint32_t, 256>& getCrc32Table() {
    static const auto table = []() {
        std::array<uint32_t, 256> t{};
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (size_t j = 0; j < 8; ++j) {
                c = (c & 1) ? (0xEDB88320L ^ (c >> 1)) : (c >> 1);
            }
            t[i] = c;
        }
        return t;
    }();
    return table;
}

} // anonymous namespace

uint32_t CryptoHash::crc32(const uint8_t* data, size_t length, uint32_t initialCrc) {
    const auto& table = getCrc32Table();
    uint32_t crc = initialCrc ^ 0xFFFFFFFF;
    for (size_t i = 0; i < length; ++i) {
        crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFF;
}

uint32_t CryptoHash::crc32(const ByteBuffer& buffer, uint32_t initialCrc) {
    return crc32(buffer.data(), buffer.size(), initialCrc);
}

// ---------------- Shannon Entropy Implementation ----------------

double CryptoHash::calculateEntropy(const uint8_t* data, size_t length) {
    if (!data || length == 0) {
        return 0.0;
    }

    uint64_t frequencies[256] = {0};
    for (size_t i = 0; i < length; ++i) {
        frequencies[data[i]]++;
    }

    double entropy = 0.0;
    double dLength = static_cast<double>(length);

    for (size_t i = 0; i < 256; ++i) {
        if (frequencies[i] > 0) {
            double p = static_cast<double>(frequencies[i]) / dLength;
            entropy -= p * std::log2(p);
        }
    }

    return entropy;
}

double CryptoHash::calculateEntropy(const ByteBuffer& buffer) {
    return calculateEntropy(buffer.data(), buffer.size());
}

} // namespace forensivault
