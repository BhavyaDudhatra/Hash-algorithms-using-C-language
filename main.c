#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <windows.h>

/* ==================== Helper Functions ==================== */

static uint32_t rotr32(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }
static uint32_t rotl32(uint32_t x, unsigned n) { return (x << n) | (x >> (32 - n)); }
static uint64_t rotr64(uint64_t x, unsigned n) { return (x >> n) | (x << (64 - n)); }
static uint64_t rotl64(uint64_t x, unsigned n) { return (x << n) | (x >> (64 - n)); }

static uint32_t load32be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static uint64_t load64be(const uint8_t *p) {
    return ((uint64_t)load32be(p) << 32) | (uint64_t)load32be(p + 4);
}
static uint32_t load32le(const uint8_t *p) {
    return ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) | ((uint32_t)p[1] << 8) | (uint32_t)p[0];
}
static uint64_t load64le(const uint8_t *p) {
    return ((uint64_t)load32le(p + 4) << 32) | (uint64_t)load32le(p);
}
static void store32be(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}
static void store64be(uint8_t *p, uint64_t v) {
    store32be(p, (uint32_t)(v >> 32)); store32be(p + 4, (uint32_t)v);
}
static void store32le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static void store64le(uint8_t *p, uint64_t v) {
    store32le(p, (uint32_t)v); store32le(p + 4, (uint32_t)(v >> 32));
}
static void bytes_to_hex(const uint8_t *bytes, size_t n, char *out) {
    static const char hexd[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i * 2]     = hexd[bytes[i] >> 4];
        out[i * 2 + 1] = hexd[bytes[i] & 15];
    }
    out[n * 2] = '\0';
}
static uint8_t *alloc_pad(size_t pad_len) {
    uint8_t *buf = (uint8_t *)calloc(pad_len, 1);
    if (!buf) { fprintf(stderr, "out of memory\n"); exit(1); }
    return buf;
}

/* Enough for the longest message (4095 bytes) accepted by the CLI, so the
 * hot crack loop never touches the (shared, lock-protected) heap. */
#define PAD_STACK 4224

/* ==================== MD5 (RFC 1321) ==================== */

static void md5_raw(const char *msg, uint8_t out[16]) {
    static const uint32_t K[64] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
    };
    static const unsigned S[64] = {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    };
    uint32_t h[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
    size_t len = strlen(msg);
    size_t pad_len = (len + 1 + 8 + 63) & ~(size_t)63;
    uint8_t sbuf[PAD_STACK];
    uint8_t *buf = sbuf;
    if (pad_len > sizeof sbuf) buf = alloc_pad(pad_len);
    else memset(buf, 0, pad_len);
    memcpy(buf, msg, len);
    buf[len] = 0x80;
    store64le(buf + pad_len - 8, (uint64_t)len * 8);

    for (size_t off = 0; off < pad_len; off += 64) {
        uint32_t w[16];
        for (int i = 0; i < 16; i++) w[i] = load32le(buf + off + (size_t)i * 4);
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        for (int i = 0; i < 64; i++) {
            uint32_t f, g;
            if (i < 16)      { f = (b & c) | (~b & d); g = (uint32_t)i; }
            else if (i < 32) { f = (d & b) | (~d & c); g = (uint32_t)((5 * i + 1) % 16); }
            else if (i < 48) { f = b ^ c ^ d;           g = (uint32_t)((3 * i + 5) % 16); }
            else             { f = c ^ (b | ~d);        g = (uint32_t)((7 * i) % 16); }
            uint32_t tmp = d;
            d = c; c = b;
            b = b + rotl32(a + f + K[i] + w[g], S[i]);
            a = tmp;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    }
    if (buf != sbuf) free(buf);
    for (int i = 0; i < 4; i++) store32le(out + (size_t)i * 4, h[i]);
}

static void md5_hex(const char *msg, char *out) {
    uint8_t d[16];
    md5_raw(msg, d);
    bytes_to_hex(d, 16, out);
}

/* ==================== SHA-1 (FIPS 180-4) ==================== */

static void sha1_raw(const char *msg, uint8_t out[20]) {
    uint32_t h[5] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0};
    size_t len = strlen(msg);
    size_t pad_len = (len + 1 + 8 + 63) & ~(size_t)63;
    uint8_t sbuf[PAD_STACK];
    uint8_t *buf = sbuf;
    if (pad_len > sizeof sbuf) buf = alloc_pad(pad_len);
    else memset(buf, 0, pad_len);
    memcpy(buf, msg, len);
    buf[len] = 0x80;
    store64be(buf + pad_len - 8, (uint64_t)len * 8);

    for (size_t off = 0; off < pad_len; off += 64) {
        uint32_t w[80];
        for (int i = 0; i < 16; i++) w[i] = load32be(buf + off + (size_t)i * 4);
        for (int i = 16; i < 80; i++) w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        for (int i = 0; i < 80; i++) {
            uint32_t f, k;
            if (i < 20)      { f = (b & c) | (~b & d);   k = 0x5a827999; }
            else if (i < 40) { f = b ^ c ^ d;            k = 0x6ed9eba1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
            else             { f = b ^ c ^ d;            k = 0xca62c1d6; }
            uint32_t tmp = rotl32(a, 5) + f + e + k + w[i];
            e = d; d = c; c = rotl32(b, 30); b = a; a = tmp;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
    }
    if (buf != sbuf) free(buf);
    for (int i = 0; i < 5; i++) store32be(out + (size_t)i * 4, h[i]);
}

static void sha1_hex(const char *msg, char *out) {
    uint8_t d[20];
    sha1_raw(msg, d);
    bytes_to_hex(d, 20, out);
}

/* ==================== SHA-2 Family (FIPS 180-4) ==================== */

static const uint32_t IV256[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};
static const uint32_t IV224[8] = {
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
    0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
};
static const uint64_t IV512[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};
static const uint64_t IV384[8] = {
    0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
    0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL, 0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL
};
static const uint64_t IV512_224[8] = {
    0x8c3d37c819544da2ULL, 0x73e1996689dcd4d6ULL, 0x1dfab7ae32ff9c82ULL, 0x679dd514582f9fcfULL,
    0x0f6d2b697bd44da8ULL, 0x77e36f7304c48942ULL, 0x3f9d85a86a1d36c8ULL, 0x1112e6ad91d692a1ULL
};
static const uint64_t IV512_256[8] = {
    0x22312194fc2bf72cULL, 0x9f555fa3c84c64c2ULL, 0x2393b86b6f53b151ULL, 0x963877195940eabdULL,
    0x96283ee2a88effe3ULL, 0xbe5e1e2553863992ULL, 0x2b0199fc2c85b8aaULL, 0x0eb72ddc81c52ca2ULL
};

static void sha256_calc(const uint32_t iv[8], const char *msg, uint8_t out[32]) {
    static const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
    uint32_t h[8];
    memcpy(h, iv, sizeof(h));
    size_t len = strlen(msg);
    size_t pad_len = (len + 1 + 8 + 63) & ~(size_t)63;
    uint8_t sbuf[PAD_STACK];
    uint8_t *buf = sbuf;
    if (pad_len > sizeof sbuf) buf = alloc_pad(pad_len);
    else memset(buf, 0, pad_len);
    memcpy(buf, msg, len);
    buf[len] = 0x80;
    store64be(buf + pad_len - 8, (uint64_t)len * 8);

    for (size_t off = 0; off < pad_len; off += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++) w[i] = load32be(buf + off + (size_t)i * 4);
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + s1 + ch + K[i] + w[i];
            uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
            uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = s0 + mj;
            hh = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    if (buf != sbuf) free(buf);
    for (int i = 0; i < 8; i++) store32be(out + (size_t)i * 4, h[i]);
}

static void sha512_calc(const uint64_t iv[8], const char *msg, uint8_t out[64]) {
    static const uint64_t K[80] = {
        0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
        0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
        0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
        0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
        0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
        0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
        0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
        0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
        0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
        0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
        0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
        0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
        0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
        0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
        0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
        0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
        0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
        0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
        0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
        0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
    };
    uint64_t h[8];
    memcpy(h, iv, sizeof(h));
    size_t len = strlen(msg);
    size_t pad_len = (len + 1 + 16 + 127) & ~(size_t)127;
    uint8_t sbuf[PAD_STACK];
    uint8_t *buf = sbuf;
    if (pad_len > sizeof sbuf) buf = alloc_pad(pad_len);
    else memset(buf, 0, pad_len);
    memcpy(buf, msg, len);
    buf[len] = 0x80;
    store64be(buf + pad_len - 8, (uint64_t)len * 8);

    for (size_t off = 0; off < pad_len; off += 128) {
        uint64_t w[80];
        for (int i = 0; i < 16; i++) w[i] = load64be(buf + off + (size_t)i * 8);
        for (int i = 16; i < 80; i++) {
            uint64_t s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
            uint64_t s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint64_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint64_t e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 80; i++) {
            uint64_t s1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
            uint64_t ch = (e & f) ^ (~e & g);
            uint64_t t1 = hh + s1 + ch + K[i] + w[i];
            uint64_t s0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
            uint64_t mj = (a & b) ^ (a & c) ^ (b & c);
            uint64_t t2 = s0 + mj;
            hh = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    if (buf != sbuf) free(buf);
    for (int i = 0; i < 8; i++) store64be(out + (size_t)i * 8, h[i]);
}

static void sha224_raw(const char *msg, uint8_t out[28]) {
    uint8_t d[32];
    sha256_calc(IV224, msg, d);
    memcpy(out, d, 28);
}
static void sha256_raw(const char *msg, uint8_t out[32]) {
    sha256_calc(IV256, msg, out);
}
static void sha384_raw(const char *msg, uint8_t out[48]) {
    uint8_t d[64];
    sha512_calc(IV384, msg, d);
    memcpy(out, d, 48);
}
static void sha512_raw(const char *msg, uint8_t out[64]) {
    sha512_calc(IV512, msg, out);
}
static void sha512_224_raw(const char *msg, uint8_t out[28]) {
    uint8_t d[64];
    sha512_calc(IV512_224, msg, d);
    memcpy(out, d, 28);
}
static void sha512_256_raw(const char *msg, uint8_t out[32]) {
    uint8_t d[64];
    sha512_calc(IV512_256, msg, d);
    memcpy(out, d, 32);
}

static void sha224_hex(const char *msg, char *out) {
    uint8_t d[28];
    sha224_raw(msg, d);
    bytes_to_hex(d, 28, out);
}
static void sha256_hex(const char *msg, char *out) {
    uint8_t d[32];
    sha256_raw(msg, d);
    bytes_to_hex(d, 32, out);
}
static void sha384_hex(const char *msg, char *out) {
    uint8_t d[48];
    sha384_raw(msg, d);
    bytes_to_hex(d, 48, out);
}
static void sha512_hex(const char *msg, char *out) {
    uint8_t d[64];
    sha512_raw(msg, d);
    bytes_to_hex(d, 64, out);
}
static void sha512_224_hex(const char *msg, char *out) {
    uint8_t d[28];
    sha512_224_raw(msg, d);
    bytes_to_hex(d, 28, out);
}
static void sha512_256_hex(const char *msg, char *out) {
    uint8_t d[32];
    sha512_256_raw(msg, d);
    bytes_to_hex(d, 32, out);
}

/* ==================== SHA-3 / SHAKE (Keccak-f[1600], FIPS 202) ==================== */

static const uint64_t KECCAK_RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};
static const int KECCAK_ROT[5][5] = {
    { 0, 36,  3, 41, 18},
    { 1, 44, 10, 45,  2},
    {62,  6, 43, 15, 61},
    {28, 55, 25, 21, 56},
    {27, 20, 39,  8, 14}
};

static void keccakf(uint64_t st[25]) {
    for (int round = 0; round < 24; round++) {
        uint64_t c[5], d[5], b[25];
        for (int x = 0; x < 5; x++)
            c[x] = st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20];
        for (int x = 0; x < 5; x++)
            d[x] = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
        for (int x = 0; x < 5; x++)
            for (int y = 0; y < 5; y++)
                st[x + 5 * y] ^= d[x];
        for (int x = 0; x < 5; x++)
            for (int y = 0; y < 5; y++)
                b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(st[x + 5 * y], (unsigned)KECCAK_ROT[x][y]);
        for (int x = 0; x < 5; x++)
            for (int y = 0; y < 5; y++)
                st[x + 5 * y] = b[x + 5 * y] ^ ((~b[((x + 1) % 5) + 5 * y]) & b[((x + 2) % 5) + 5 * y]);
        st[0] ^= KECCAK_RC[round];
    }
}

static void sponge_raw(const char *msg, uint8_t suffix, size_t rate,
                       size_t out_bytes, uint8_t *out) {
    uint64_t st[25];
    memset(st, 0, sizeof(st));
    size_t len = strlen(msg);
    size_t off = 0;
    while (len - off >= rate) {
        for (size_t i = 0; i < rate; i++)
            ((uint8_t *)st)[i] ^= (uint8_t)msg[off + i];
        keccakf(st);
        off += rate;
    }
    uint8_t last[168];
    memset(last, 0, sizeof(last));
    size_t rem = len - off;
    memcpy(last, msg + off, rem);
    last[rem] |= suffix;
    last[rate - 1] |= 0x80;
    for (size_t i = 0; i < rate; i++)
        ((uint8_t *)st)[i] ^= last[i];
    keccakf(st);

    size_t produced = 0;
    while (produced < out_bytes) {
        size_t take = rate;
        if (take > out_bytes - produced) take = out_bytes - produced;
        memcpy(out + produced, st, take);
        produced += take;
        if (produced < out_bytes) keccakf(st);
    }
}

static void sha3_224_raw(const char *msg, uint8_t out[28]) { sponge_raw(msg, 0x06, 144, 28, out); }
static void sha3_256_raw(const char *msg, uint8_t out[32]) { sponge_raw(msg, 0x06, 136, 32, out); }
static void sha3_384_raw(const char *msg, uint8_t out[48]) { sponge_raw(msg, 0x06, 104, 48, out); }
static void sha3_512_raw(const char *msg, uint8_t out[64]) { sponge_raw(msg, 0x06,  72, 64, out); }
static void shake128_raw(const char *msg, uint8_t out[32]) { sponge_raw(msg, 0x1f, 168, 32, out); }
static void shake256_raw(const char *msg, uint8_t out[64]) { sponge_raw(msg, 0x1f, 136, 64, out); }

static void sha3_224_hex(const char *msg, char *out) { uint8_t d[28]; sha3_224_raw(msg, d); bytes_to_hex(d, 28, out); }
static void sha3_256_hex(const char *msg, char *out) { uint8_t d[32]; sha3_256_raw(msg, d); bytes_to_hex(d, 32, out); }
static void sha3_384_hex(const char *msg, char *out) { uint8_t d[48]; sha3_384_raw(msg, d); bytes_to_hex(d, 48, out); }
static void sha3_512_hex(const char *msg, char *out) { uint8_t d[64]; sha3_512_raw(msg, d); bytes_to_hex(d, 64, out); }
static void shake128_hex(const char *msg, char *out) { uint8_t d[32]; shake128_raw(msg, d); bytes_to_hex(d, 32, out); }
static void shake256_hex(const char *msg, char *out) { uint8_t d[64]; shake256_raw(msg, d); bytes_to_hex(d, 64, out); }

/* ==================== BLAKE2b / BLAKE2s (RFC 7693) ==================== */

static const uint8_t BLAKE2_SIGMA[12][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3},
    {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4},
    { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8},
    { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13},
    { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9},
    {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11},
    {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10},
    { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0},
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3}
};

static void b2b_g(uint64_t *a, uint64_t *b, uint64_t *c, uint64_t *d,
                   uint64_t x, uint64_t y) {
    *a = *a + *b + x;
    *d = rotr64(*d ^ *a, 32);
    *c = *c + *d;
    *b = rotr64(*b ^ *c, 24);
    *a = *a + *b + y;
    *d = rotr64(*d ^ *a, 16);
    *c = *c + *d;
    *b = rotr64(*b ^ *c, 63);
}

static void blake2b_compress(uint64_t h[8], const uint8_t block[128],
                             uint64_t t, uint64_t f) {
    uint64_t m[16];
    for (int i = 0; i < 16; i++) m[i] = load64le(block + (size_t)i * 8);
    uint64_t v[16] = {
        h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7],
        IV512[0], IV512[1], IV512[2], IV512[3],
        IV512[4], IV512[5], IV512[6], IV512[7]
    };
    v[12] ^= t;
    v[14] ^= f;
    for (int r = 0; r < 12; r++) {
        const uint8_t *s = BLAKE2_SIGMA[r];
        b2b_g(&v[0], &v[4], &v[8],  &v[12], m[s[0]],  m[s[1]]);
        b2b_g(&v[1], &v[5], &v[9],  &v[13], m[s[2]],  m[s[3]]);
        b2b_g(&v[2], &v[6], &v[10], &v[14], m[s[4]],  m[s[5]]);
        b2b_g(&v[3], &v[7], &v[11], &v[15], m[s[6]],  m[s[7]]);
        b2b_g(&v[0], &v[5], &v[10], &v[15], m[s[8]],  m[s[9]]);
        b2b_g(&v[1], &v[6], &v[11], &v[12], m[s[10]], m[s[11]]);
        b2b_g(&v[2], &v[7], &v[8],  &v[13], m[s[12]], m[s[13]]);
        b2b_g(&v[3], &v[4], &v[9],  &v[14], m[s[14]], m[s[15]]);
    }
    for (int i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
}

static void blake2b_raw(const char *msg, uint8_t out[64]) {
    uint64_t h[8];
    memcpy(h, IV512, sizeof(h));
    h[0] ^= 0x01010040ULL;
    const uint8_t *p = (const uint8_t *)msg;
    size_t len = strlen(msg);
    uint64_t t = 0;
    while (len > 128) {
        t += 128;
        blake2b_compress(h, p, t, 0);
        p += 128;
        len -= 128;
    }
    uint8_t block[128];
    memset(block, 0, sizeof(block));
    memcpy(block, p, len);
    t += len;
    blake2b_compress(h, block, t, ~(uint64_t)0);
    for (int i = 0; i < 8; i++) store64le(out + (size_t)i * 8, h[i]);
}

static void blake2b_hex(const char *msg, char *out) {
    uint8_t d[64];
    blake2b_raw(msg, d);
    bytes_to_hex(d, 64, out);
}

static void b2s_g(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d,
                   uint32_t x, uint32_t y) {
    *a = *a + *b + x;
    *d = rotr32(*d ^ *a, 16);
    *c = *c + *d;
    *b = rotr32(*b ^ *c, 12);
    *a = *a + *b + y;
    *d = rotr32(*d ^ *a, 8);
    *c = *c + *d;
    *b = rotr32(*b ^ *c, 7);
}

static void blake2s_compress(uint32_t h[8], const uint8_t block[64],
                             uint64_t t, uint64_t f) {
    uint32_t m[16];
    for (int i = 0; i < 16; i++) m[i] = load32le(block + (size_t)i * 4);
    uint32_t v[16] = {
        h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7],
        IV256[0], IV256[1], IV256[2], IV256[3],
        IV256[4], IV256[5], IV256[6], IV256[7]
    };
    v[12] ^= (uint32_t)t;
    v[13] ^= (uint32_t)(t >> 32);
    v[14] ^= (uint32_t)f;
    for (int r = 0; r < 10; r++) {
        const uint8_t *s = BLAKE2_SIGMA[r];
        b2s_g(&v[0], &v[4], &v[8],  &v[12], m[s[0]],  m[s[1]]);
        b2s_g(&v[1], &v[5], &v[9],  &v[13], m[s[2]],  m[s[3]]);
        b2s_g(&v[2], &v[6], &v[10], &v[14], m[s[4]],  m[s[5]]);
        b2s_g(&v[3], &v[7], &v[11], &v[15], m[s[6]],  m[s[7]]);
        b2s_g(&v[0], &v[5], &v[10], &v[15], m[s[8]],  m[s[9]]);
        b2s_g(&v[1], &v[6], &v[11], &v[12], m[s[10]], m[s[11]]);
        b2s_g(&v[2], &v[7], &v[8],  &v[13], m[s[12]], m[s[13]]);
        b2s_g(&v[3], &v[4], &v[9],  &v[14], m[s[14]], m[s[15]]);
    }
    for (int i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
}

static void blake2s_raw(const char *msg, uint8_t out[32]) {
    uint32_t h[8];
    memcpy(h, IV256, sizeof(h));
    h[0] ^= 0x01010020U;
    const uint8_t *p = (const uint8_t *)msg;
    size_t len = strlen(msg);
    uint64_t t = 0;
    while (len > 64) {
        t += 64;
        blake2s_compress(h, p, t, 0);
        p += 64;
        len -= 64;
    }
    uint8_t block[64];
    memset(block, 0, sizeof(block));
    memcpy(block, p, len);
    t += len;
    blake2s_compress(h, block, t, ~(uint64_t)0);
    for (int i = 0; i < 8; i++) store32le(out + (size_t)i * 4, h[i]);
}

static void blake2s_hex(const char *msg, char *out) {
    uint8_t d[32];
    blake2s_raw(msg, d);
    bytes_to_hex(d, 32, out);
}

/* ==================== BLAKE3 ==================== */

#define B3_CHUNK_START 1u
#define B3_CHUNK_END   2u
#define B3_PARENT      4u
#define B3_ROOT        8u

static const uint32_t B3_IV[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};
static const uint8_t B3_PERM[16] = {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8};

static void b3_g(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d,
                  uint32_t mx, uint32_t my) {
    *a = *a + *b + mx;
    *d = rotr32(*d ^ *a, 16);
    *c = *c + *d;
    *b = rotr32(*b ^ *c, 12);
    *a = *a + *b + my;
    *d = rotr32(*d ^ *a, 8);
    *c = *c + *d;
    *b = rotr32(*b ^ *c, 7);
}

static void b3_compress(const uint32_t state[8], const uint32_t block[16],
                        uint64_t counter, uint8_t block_len, uint32_t flags,
                        uint32_t out[16]) {
    uint32_t v[16] = {
        state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
        B3_IV[0], B3_IV[1], B3_IV[2], B3_IV[3],
        (uint32_t)counter, (uint32_t)(counter >> 32), (uint32_t)block_len, flags
    };
    uint32_t m[16];
    memcpy(m, block, sizeof(m));
    for (int r = 0; r < 7; r++) {
        b3_g(&v[0], &v[4], &v[8],  &v[12], m[0],  m[1]);
        b3_g(&v[1], &v[5], &v[9],  &v[13], m[2],  m[3]);
        b3_g(&v[2], &v[6], &v[10], &v[14], m[4],  m[5]);
        b3_g(&v[3], &v[7], &v[11], &v[15], m[6],  m[7]);
        b3_g(&v[0], &v[5], &v[10], &v[15], m[8],  m[9]);
        b3_g(&v[1], &v[6], &v[11], &v[12], m[10], m[11]);
        b3_g(&v[2], &v[7], &v[8],  &v[13], m[12], m[13]);
        b3_g(&v[3], &v[4], &v[9],  &v[14], m[14], m[15]);
        if (r < 6) {
            uint32_t p[16];
            for (int i = 0; i < 16; i++) p[i] = m[B3_PERM[i]];
            memcpy(m, p, sizeof(m));
        }
    }
    for (int i = 0; i < 8; i++) {
        out[i] = v[i] ^ v[i + 8];
        out[8 + i] = v[i + 8] ^ state[i];
    }
}

/* Complete 1024-byte (or shorter, final) chunk -> chaining value. */
static void b3_chunk_cv(const uint8_t *chunk, size_t chunk_len,
                        uint64_t counter, int is_root, uint32_t cv[8]) {
    uint32_t state[8];
    memcpy(state, B3_IV, sizeof(state));
    if (is_root) counter = 0;
    if (chunk_len == 0) {
        uint32_t zeros[16] = {0};
        uint32_t o[16];
        uint32_t fl = B3_CHUNK_START | B3_CHUNK_END;
        if (is_root) fl |= B3_ROOT;
        b3_compress(state, zeros, counter, 0, fl, o);
        memcpy(cv, o, 32);
        return;
    }
    size_t off = 0;
    while (off < chunk_len) {
        uint8_t buf[64];
        uint32_t block[16];
        uint32_t o[16];
        size_t take = chunk_len - off;
        if (take > 64) take = 64;
        memset(buf, 0, sizeof(buf));
        memcpy(buf, chunk + off, take);
        for (int i = 0; i < 16; i++) block[i] = load32le(buf + (size_t)i * 4);
        uint32_t flags = 0;
        if (off == 0) flags |= B3_CHUNK_START;
        if (off + take == chunk_len) {
            flags |= B3_CHUNK_END;
            if (is_root) flags |= B3_ROOT;
        }
        b3_compress(state, block, counter, (uint8_t)take, flags, o);
        memcpy(state, o, 32);
        off += take;
    }
    memcpy(cv, state, 32);
}

static void b3_parent_cv(const uint32_t l[8], const uint32_t r[8], int is_root,
                         uint32_t out[8]) {
    uint8_t buf[64];
    uint32_t block[16];
    uint32_t o[16];
    uint32_t state[8];
    for (int i = 0; i < 8; i++) {
        store32le(buf + (size_t)i * 4, l[i]);
        store32le(buf + 32 + (size_t)i * 4, r[i]);
    }
    for (int i = 0; i < 16; i++) block[i] = load32le(buf + (size_t)i * 4);
    memcpy(state, B3_IV, sizeof(state));
    b3_compress(state, block, 0, 64, B3_PARENT | (is_root ? B3_ROOT : 0), o);
    memcpy(out, o, 32);
}

static void b3_add_cv(uint32_t stack[54][8], size_t *stack_len,
                      const uint32_t cv[8], uint64_t total_chunks) {
    memcpy(stack[*stack_len], cv, 32);
    (*stack_len)++;
    while ((total_chunks & 1) == 0) {
        uint32_t parent[8];
        b3_parent_cv(stack[*stack_len - 2], stack[*stack_len - 1], 0, parent);
        memcpy(stack[*stack_len - 2], parent, 32);
        (*stack_len)--;
        total_chunks >>= 1;
    }
}

static void blake3_raw(const char *msg, uint8_t out[32]) {
    const uint8_t *in = (const uint8_t *)msg;
    size_t total = strlen(msg);
    uint32_t stack[54][8];
    size_t stack_len = 0;
    uint64_t counter = 0;
    size_t off = 0;
    while (total - off > 1024) {
        uint32_t cv[8];
        b3_chunk_cv(in + off, 1024, counter, 0, cv);
        counter++;
        b3_add_cv(stack, &stack_len, cv, counter);
        off += 1024;
    }
    uint32_t cv[8];
    b3_chunk_cv(in + off, total - off, counter, stack_len == 0, cv);
    while (stack_len > 0) {
        uint32_t parent[8];
        stack_len--;
        b3_parent_cv(stack[stack_len], cv, stack_len == 0, parent);
        memcpy(cv, parent, 32);
    }
    for (int i = 0; i < 8; i++) store32le(out + (size_t)i * 4, cv[i]);
}

static void blake3_hex(const char *msg, char *out) {
    uint8_t d[32];
    blake3_raw(msg, d);
    bytes_to_hex(d, 32, out);
}

/* ==================== RIPEMD-160 ==================== */

static void ripemd160_raw(const char *msg, uint8_t out[20]) {
    static const uint32_t R1[80] = {
         0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
         7, 4,13, 1,10, 6,15, 3,12, 0, 9, 5, 2,14,11, 8,
         3,10,14, 4, 9,15, 8, 1, 2, 7, 0, 6,13,11, 5,12,
         1, 9,11,10, 0, 8,12, 4,13, 3, 7,15,14, 5, 6, 2,
         4, 0, 5, 9, 7,12, 2,10,14, 1, 3, 8,11, 6,15,13
    };
    static const uint32_t R2[80] = {
         5,14, 7, 0, 9, 2,11, 4,13, 6,15, 8, 1,10, 3,12,
         6,11, 3, 7, 0,13, 5,10,14,15, 8,12, 4, 9, 1, 2,
        15, 5, 1, 3, 7,14, 6, 9,11, 8,12, 2,10, 0, 4,13,
         8, 6, 4, 1, 3,11,15, 0, 5,12, 2,13, 9, 7,10,14,
        12,15,10, 4, 1, 5, 8, 7, 6, 2,13,14, 0, 3, 9,11
    };
    static const uint32_t S1[80] = {
        11,14,15,12, 5, 8, 7, 9,11,13,14,15, 6, 7, 9, 8,
         7, 6, 8,13,11, 9, 7,15, 7,12,15, 9,11, 7,13,12,
        11,13, 6, 7,14, 9,13,15,14, 8,13, 6, 5,12, 7, 5,
        11,12,14,15,14,15, 9, 8, 9,14, 5, 6, 8, 6, 5,12,
         9,15, 5,11, 6, 8,13,12, 5,12,13,14,11, 8, 5, 6
    };
    static const uint32_t S2[80] = {
         8, 9, 9,11,13,15,15, 5, 7, 7, 8,11,14,14,12, 6,
         9,13,15, 7,12, 8, 9,11, 7, 7,12, 7, 6,15,13,11,
         9, 7,15,11, 8, 6, 6,14,12,13, 5,14,13,13, 7, 5,
        15, 5, 8,11,14,14, 6,14, 6, 9,12, 9,12, 5,15, 8,
         8, 5,12, 9,12, 5,14, 6, 8,13, 6, 5,15,13,11,11
    };
    uint32_t h[5] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0};
    size_t len = strlen(msg);
    size_t pad_len = (len + 1 + 8 + 63) & ~(size_t)63;
    uint8_t sbuf[PAD_STACK];
    uint8_t *buf = sbuf;
    if (pad_len > sizeof sbuf) buf = alloc_pad(pad_len);
    else memset(buf, 0, pad_len);
    memcpy(buf, msg, len);
    buf[len] = 0x80;
    store64le(buf + pad_len - 8, (uint64_t)len * 8);

    for (size_t off = 0; off < pad_len; off += 64) {
        uint32_t x[16];
        for (int i = 0; i < 16; i++) x[i] = load32le(buf + off + (size_t)i * 4);
        uint32_t al = h[0], bl = h[1], cl = h[2], dl = h[3], el = h[4];
        uint32_t ar = h[0], br = h[1], cr = h[2], dr = h[3], er = h[4];
        for (int j = 0; j < 80; j++) {
            uint32_t fl, kl;
            switch (j / 16) {
            case 0:  fl = bl ^ cl ^ dl;           kl = 0x00000000; break;
            case 1:  fl = (bl & cl) | (~bl & dl); kl = 0x5a827999; break;
            case 2:  fl = (bl | ~cl) ^ dl;        kl = 0x6ed9eba1; break;
            case 3:  fl = (bl & dl) | (cl & ~dl); kl = 0x8f1bbcdc; break;
            default: fl = bl ^ (cl | ~dl);        kl = 0xa953fd4e; break;
            }
            uint32_t sr = al + fl + x[R1[j]] + kl;
            sr = rotl32(sr, S1[j]) + el;
            al = el; el = dl; dl = rotl32(cl, 10); cl = bl; bl = sr;

            uint32_t fr, kr;
            switch (j / 16) {
            case 0:  fr = br ^ (cr | ~dr);        kr = 0x50a28be6; break;
            case 1:  fr = (br & dr) | (cr & ~dr); kr = 0x5c4dd124; break;
            case 2:  fr = (br | ~cr) ^ dr;        kr = 0x6d703ef3; break;
            case 3:  fr = (br & cr) | (~br & dr); kr = 0x7a6d76e9; break;
            default: fr = br ^ cr ^ dr;           kr = 0x00000000; break;
            }
            sr = ar + fr + x[R2[j]] + kr;
            sr = rotl32(sr, S2[j]) + er;
            ar = er; er = dr; dr = rotl32(cr, 10); cr = br; br = sr;
        }
        uint32_t t = h[1] + cl + dr;
        h[1] = h[2] + dl + er;
        h[2] = h[3] + el + ar;
        h[3] = h[4] + al + br;
        h[4] = h[0] + bl + cr;
        h[0] = t;
    }
    if (buf != sbuf) free(buf);
    for (int i = 0; i < 5; i++) store32le(out + (size_t)i * 4, h[i]);
}

static void ripemd160_hex(const char *msg, char *out) {
    uint8_t d[20];
    ripemd160_raw(msg, d);
    bytes_to_hex(d, 20, out);
}

/* ==================== Whirlpool (ISO/IEC 10118-3:2004) ==================== */

static const uint8_t WP_SBOX[256] = {
    0x18,0x23,0xc6,0xe8,0x87,0xb8,0x01,0x4f,0x36,0xa6,0xd2,0xf5,0x79,0x6f,0x91,0x52,
    0x60,0xbc,0x9b,0x8e,0xa3,0x0c,0x7b,0x35,0x1d,0xe0,0xd7,0xc2,0x2e,0x4b,0xfe,0x57,
    0x15,0x77,0x37,0xe5,0x9f,0xf0,0x4a,0xda,0x58,0xc9,0x29,0x0a,0xb1,0xa0,0x6b,0x85,
    0xbd,0x5d,0x10,0xf4,0xcb,0x3e,0x05,0x67,0xe4,0x27,0x41,0x8b,0xa7,0x7d,0x95,0xd8,
    0xfb,0xee,0x7c,0x66,0xdd,0x17,0x47,0x9e,0xca,0x2d,0xbf,0x07,0xad,0x5a,0x83,0x33,
    0x63,0x02,0xaa,0x71,0xc8,0x19,0x49,0xd9,0xf2,0xe3,0x5b,0x88,0x9a,0x26,0x32,0xb0,
    0xe9,0x0f,0xd5,0x80,0xbe,0xcd,0x34,0x48,0xff,0x7a,0x90,0x5f,0x20,0x68,0x1a,0xae,
    0xb4,0x54,0x93,0x22,0x64,0xf1,0x73,0x12,0x40,0x08,0xc3,0xec,0xdb,0xa1,0x8d,0x3d,
    0x97,0x00,0xcf,0x2b,0x76,0x82,0xd6,0x1b,0xb5,0xaf,0x6a,0x50,0x45,0xf3,0x30,0xef,
    0x3f,0x55,0xa2,0xea,0x65,0xba,0x2f,0xc0,0xde,0x1c,0xfd,0x4d,0x92,0x75,0x06,0x8a,
    0xb2,0xe6,0x0e,0x1f,0x62,0xd4,0xa8,0x96,0xf9,0xc5,0x25,0x59,0x84,0x72,0x39,0x4c,
    0x5e,0x78,0x38,0x8c,0xd1,0xa5,0xe2,0x61,0xb3,0x21,0x9c,0x1e,0x43,0xc7,0xfc,0x04,
    0x51,0x99,0x6d,0x0d,0xfa,0xdf,0x7e,0x24,0x3b,0xab,0xce,0x11,0x8f,0x4e,0xb7,0xeb,
    0x3c,0x81,0x94,0xf7,0xb9,0x13,0x2c,0xd3,0xe7,0x6e,0xc4,0x03,0x56,0x44,0x7f,0xa9,
    0x2a,0xbb,0xc1,0x53,0xdc,0x0b,0x9d,0x6c,0x31,0x74,0xf6,0x46,0xac,0x89,0x14,0xe1,
    0x16,0x3a,0x69,0x09,0x70,0xb6,0xd0,0xed,0xcc,0x42,0x98,0xa4,0x28,0x5c,0xf8,0x86
};

static uint8_t wp_xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ (0x1du & (uint8_t)(0u - (x >> 7))));
}

/* S-box composed with the MDS row [1,1,4,1,8,5,2,9] (primary round table). */
static uint64_t wp_c0(uint8_t x) {
    uint64_t v1 = WP_SBOX[x];
    uint64_t v2 = wp_xtime((uint8_t)v1);
    uint64_t v4 = wp_xtime((uint8_t)v2);
    uint64_t v5 = v4 ^ v1;
    uint64_t v8 = wp_xtime((uint8_t)v4);
    uint64_t v9 = v8 ^ v1;
    return (v1 << 56) | (v1 << 48) | (v4 << 40) | (v1 << 32) |
           (v8 << 24) | (v5 << 16) | (v2 << 8)  | v9;
}

static uint64_t WP_C0[256];
static int WP_C0_READY = 0;

static void wp_init(void) {
    if (WP_C0_READY) return;
    for (int i = 0; i < 256; i++) WP_C0[i] = wp_c0((uint8_t)i);
    WP_C0_READY = 1;
}

static void wp_theta(const uint64_t in[8], uint64_t out[8], const uint64_t c0[256]) {
    for (int i = 0; i < 8; i++) {
        uint64_t acc = 0;
        for (int t = 0; t < 8; t++) {
            uint64_t word = in[(i + 8 - t) & 7];
            uint8_t b = (uint8_t)(word >> (56 - 8 * t));
            acc ^= rotr64(c0[b], (unsigned)(8 * t));
        }
        out[i] = acc;
    }
}

static void wp_compress(uint64_t hash[8], const uint8_t block[64]) {
    const uint64_t *c0 = WP_C0;
    uint64_t m[8], k[8], state[8], tmp[8];
    for (int i = 0; i < 8; i++) {
        m[i] = load64be(block + (size_t)i * 8);
        k[i] = hash[i];
        state[i] = m[i] ^ k[i];
    }
    for (int r = 0; r < 10; r++) {
        wp_theta(k, tmp, c0);
        for (int i = 0; i < 8; i++) k[i] = tmp[i];
        /* Round constant: first row only, bytes S[8r .. 8r+7] big-endian. */
        {
            uint64_t rc = 0;
            for (int j = 0; j < 8; j++) rc = (rc << 8) | WP_SBOX[8 * r + j];
            k[0] ^= rc;
        }
        wp_theta(state, tmp, c0);
        for (int i = 0; i < 8; i++) state[i] = tmp[i] ^ k[i];
    }
    for (int i = 0; i < 8; i++) hash[i] ^= state[i] ^ m[i];
}

static void whirlpool_raw(const char *msg, uint8_t out[64]) {
    uint64_t hash[8];
    memset(hash, 0, sizeof(hash));
    size_t len = strlen(msg);
    size_t pad_len = (len + 1 + 32 + 63) & ~(size_t)63;
    uint8_t sbuf[PAD_STACK];
    uint8_t *buf = sbuf;
    if (pad_len > sizeof sbuf) buf = alloc_pad(pad_len);
    else memset(buf, 0, pad_len);
    memcpy(buf, msg, len);
    buf[len] = 0x80;
    store64be(buf + pad_len - 8, (uint64_t)len * 8);

    for (size_t off = 0; off < pad_len; off += 64)
        wp_compress(hash, buf + off);
    if (buf != sbuf) free(buf);

    for (int i = 0; i < 8; i++) store64be(out + (size_t)i * 8, hash[i]);
}

static void whirlpool_hex(const char *msg, char *out) {
    uint8_t d[64];
    whirlpool_raw(msg, d);
    bytes_to_hex(d, 64, out);
}

/* ==================== CRC-32 / CRC-64 ==================== */

static uint32_t calculate_crc32(const char *str) {
    uint32_t crc = 0xFFFFFFFFu;
    size_t len = strlen(str);
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint8_t)str[i];
        for (int j = 0; j < 8; j++)
            crc = (crc & 1) ? (crc >> 1) ^ 0xEDB88320u : (crc >> 1);
    }
    return ~crc;
}

static uint64_t calculate_crc64(const char *str) {
    uint64_t crc = 0xFFFFFFFFFFFFFFFFULL;
    uint64_t poly = 0xC96C5795D7870F42ULL;
    size_t len = strlen(str);
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint64_t)(uint8_t)str[i];
        for (int j = 0; j < 8; j++)
            crc = (crc & 1) ? (crc >> 1) ^ poly : (crc >> 1);
    }
    return crc ^ 0xFFFFFFFFFFFFFFFFULL;
}

/* ==================== Category-wise Display ==================== */

static void crc32_raw(const char *msg, uint8_t out[4]) {
    store32be(out, calculate_crc32(msg));
}
static void crc64_raw(const char *msg, uint8_t out[8]) {
    store64be(out, calculate_crc64(msg));
}
static void crc32_hex(const char *msg, char *out) {
    sprintf(out, "%08" PRIx32, calculate_crc32(msg));
}
static void crc64_hex(const char *msg, char *out) {
    sprintf(out, "%016" PRIx64, calculate_crc64(msg));
}

static void print_entry(const char *name, const char *hash) {
    printf("  %-16s: %s\n", name, hash);
}

struct algo {
    const char *name;
    void (*fn)(const char *, char *);
    void (*fn_raw)(const char *, uint8_t *);
    size_t digest_len;
};

static const struct algo ALGOS[] = {
    { "MD5",         md5_hex,         md5_raw,         16 },
    { "SHA-1",       sha1_hex,        sha1_raw,        20 },
    { "SHA-224",     sha224_hex,      sha224_raw,      28 },
    { "SHA-256",     sha256_hex,      sha256_raw,      32 },
    { "SHA-384",     sha384_hex,      sha384_raw,      48 },
    { "SHA-512",     sha512_hex,      sha512_raw,      64 },
    { "SHA-512/224", sha512_224_hex,  sha512_224_raw,  28 },
    { "SHA-512/256", sha512_256_hex,  sha512_256_raw,  32 },
    { "SHA3-224",    sha3_224_hex,    sha3_224_raw,    28 },
    { "SHA3-256",    sha3_256_hex,    sha3_256_raw,    32 },
    { "SHA3-384",    sha3_384_hex,    sha3_384_raw,    48 },
    { "SHA3-512",    sha3_512_hex,    sha3_512_raw,    64 },
    { "SHAKE128",    shake128_hex,    shake128_raw,    32 },
    { "SHAKE256",    shake256_hex,    shake256_raw,    64 },
    { "BLAKE2b",     blake2b_hex,     blake2b_raw,     64 },
    { "BLAKE2s",     blake2s_hex,     blake2s_raw,     32 },
    { "BLAKE3",      blake3_hex,      blake3_raw,      32 },
    { "RIPEMD-160",  ripemd160_hex,   ripemd160_raw,   20 },
    { "Whirlpool",   whirlpool_hex,   whirlpool_raw,   64 },
    { "CRC32",       crc32_hex,       crc32_raw,        4 },
    { "CRC64",       crc64_hex,       crc64_raw,        8 },
};
#define NUM_ALGOS ((int)(sizeof(ALGOS) / sizeof(ALGOS[0])))

static void show_menu(void) {
    printf("\nSelect a hash algorithm:\n");
    for (int i = 0; i < NUM_ALGOS; i++)
        printf("  %2d. %s\n", i + 1, ALGOS[i].name);
    printf("Choice: ");
    fflush(stdout);
}

static void show_one(const char *text, int choice) {
    char hex[129];

    printf("\n============================================\n");
    printf(" Hash result for plain text\n");
    printf("============================================\n");
    printf(" Plain Text : \"%s\"\n", text);
    printf("============================================\n\n");
    ALGOS[choice].fn(text, hex);
    print_entry(ALGOS[choice].name, hex);
    printf("============================================\n");
}

static int read_algo_choice(void) {
    char line[32];
    int choice = -1;
    while (choice < 1 || choice > NUM_ALGOS) {
        show_menu();
        if (!fgets(line, sizeof(line), stdin)) return -1;
        choice = (int)strtol(line, NULL, 10);
        if (choice < 1 || choice > NUM_ALGOS)
            printf("Invalid choice, please enter a number between 1 and %d.\n", NUM_ALGOS);
    }
    return choice - 1;
}

static void show_main_menu(void) {
    printf("\n============================================\n");
    printf(" Hasher - Main Menu\n");
    printf("============================================\n");
    printf("  1. Plain text to hash\n");
    printf("  2. Find plain text from hash (brute force)\n");
    printf("  3. Exit\n");
    printf("Choice: ");
    fflush(stdout);
}

static int mode_hash(void) {
    char text[4096];
    printf("Enter plain text string: ");
    fflush(stdout);
    if (!fgets(text, sizeof(text), stdin)) return -1;
    text[strcspn(text, "\r\n")] = '\0';
    int choice = read_algo_choice();
    if (choice < 0) return -1;
    show_one(text, choice);
    return 0;
}

#define CRACK_MIN_LEN 1
#define CRACK_MAX_LEN 10
#define CRACK_ALPHA_MIN 32
#define CRACK_ALPHA_MAX 127
#define CRACK_ALPHA_COUNT ((uint64_t)(CRACK_ALPHA_MAX - CRACK_ALPHA_MIN + 1))

/* The search space of each length is cut into work items of CRACK_CHUNK
 * candidates. Every worker thread atomically pulls the next item, so all
 * parts of the space are processed simultaneously, with fine-grained load
 * balancing, and no combination is ever skipped or done twice. */
#define CRACK_CHUNK 4096ULL
#define CRACK_MAX_THREADS 64 /* WaitForMultipleObjects limit */

static char g_crack_target_hex[256];
static uint8_t g_crack_target[64];
static size_t g_crack_target_len;
static int g_crack_choice;
static unsigned g_crack_len;
static volatile long long g_crack_next;     /* work-item counter */
static volatile long long g_crack_attempts; /* total candidates hashed */
static volatile int g_crack_found;
static char g_crack_plain[CRACK_MAX_LEN + 2];
static CRITICAL_SECTION g_crack_cs;

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static uint64_t pow96(int e) {
    uint64_t r = 1;
    while (e-- > 0) r *= CRACK_ALPHA_COUNT;
    return r;
}

static void cand_from_index(uint64_t idx, int len, char *cand) {
    for (int i = len - 1; i >= 0; i--) {
        cand[i] = (char)(CRACK_ALPHA_MIN + (int)(idx % CRACK_ALPHA_COUNT));
        idx /= CRACK_ALPHA_COUNT;
    }
    cand[len] = '\0';
}

static void cand_increment(char *cand, int len) {
    int p = len - 1;
    while (p >= 0 && cand[p] == (char)CRACK_ALPHA_MAX) {
        cand[p] = (char)CRACK_ALPHA_MIN;
        p--;
    }
    if (p >= 0) cand[p]++;
}

/* Returns the next work item [start, start+count) of the current length.
 * For length 10 the 66-bit index space is split into a leading digit plus a
 * 64-bit remainder, so no combination is lost to integer overflow. */
static int crack_next_range(uint64_t *start, uint64_t *count, int *hi) {
    uint64_t t = (uint64_t)__sync_fetch_and_add(&g_crack_next, 1);
    *hi = -1;
    if (g_crack_len < 10) {
        uint64_t total = pow96((int)g_crack_len);
        *start = t * CRACK_CHUNK;
        if (*start >= total) return 0;
        *count = total - *start;
        if (*count > CRACK_CHUNK) *count = CRACK_CHUNK;
        return 1;
    } else {
        uint64_t total9 = pow96(9);
        uint64_t n9 = (total9 + CRACK_CHUNK - 1) / CRACK_CHUNK;
        if (t >= CRACK_ALPHA_COUNT * n9) return 0;
        *hi = (int)(t / n9);
        *start = (t % n9) * CRACK_CHUNK;
        *count = total9 - *start;
        if (*count > CRACK_CHUNK) *count = CRACK_CHUNK;
        return 1;
    }
}

static DWORD WINAPI crack_worker(LPVOID arg) {
    char cand[CRACK_MAX_LEN + 2];
    uint8_t dig[64];
    long long local = 0;
    int len = (int)g_crack_len;
    size_t tlen = g_crack_target_len;
    (void)arg;

    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);

    while (!g_crack_found) {
        uint64_t start, count;
        int hi;
        if (!crack_next_range(&start, &count, &hi)) break;

        if (len < 10) {
            cand_from_index(start, len, cand);
        } else {
            cand[0] = (char)(CRACK_ALPHA_MIN + hi);
            cand_from_index(start, 9, cand + 1);
        }

        for (uint64_t k = 0; k < count; k++) {
            if (g_crack_found) break;
            ALGOS[g_crack_choice].fn_raw(cand, dig);
            local++;
            if (local >= 65536) {
                __sync_fetch_and_add(&g_crack_attempts, local);
                local = 0;
            }
            if (memcmp(dig, g_crack_target, tlen) == 0) {
                EnterCriticalSection(&g_crack_cs);
                if (!g_crack_found) {
                    memcpy(g_crack_plain, cand, (size_t)len + 1);
                    __sync_lock_test_and_set(&g_crack_found, 1);
                }
                LeaveCriticalSection(&g_crack_cs);
                break;
            }
            cand_increment(cand, len);
        }
        if (local) {
            __sync_fetch_and_add(&g_crack_attempts, local);
            local = 0;
        }
    }
    if (local) __sync_fetch_and_add(&g_crack_attempts, local);
    return 0;
}

static int mode_crack(void) {
    SYSTEM_INFO si;
    int nthreads, created;
    HANDLE th[CRACK_MAX_THREADS];
    const struct algo *a;

    printf("Enter hash value: ");
    fflush(stdout);
    if (!fgets(g_crack_target_hex, sizeof(g_crack_target_hex), stdin)) return -1;
    g_crack_target_hex[strcspn(g_crack_target_hex, "\r\n")] = '\0';

    g_crack_choice = read_algo_choice();
    if (g_crack_choice < 0) return -1;
    a = &ALGOS[g_crack_choice];

    {
        size_t hexlen = strlen(g_crack_target_hex);
        if (hexlen != a->digest_len * 2) {
            printf("Wrong hash length for %s: expected %lu hex characters, got %lu.\n",
                   a->name, (unsigned long)(a->digest_len * 2), (unsigned long)hexlen);
            return 1;
        }
        g_crack_target_len = a->digest_len;
        for (size_t i = 0; i < g_crack_target_len; i++) {
            int hi = hex_nibble(g_crack_target_hex[2 * i]);
            int lo = hex_nibble(g_crack_target_hex[2 * i + 1]);
            if (hi < 0 || lo < 0) {
                printf("Hash value must be hexadecimal.\n");
                return 1;
            }
            g_crack_target[i] = (uint8_t)((hi << 4) | lo);
        }
    }

    GetSystemInfo(&si);
    nthreads = (int)si.dwNumberOfProcessors;
    if (nthreads < 1) nthreads = 1;
    if (nthreads > CRACK_MAX_THREADS) nthreads = CRACK_MAX_THREADS;

    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);

    printf("\nCracking with %s (printable ASCII %d-%d, length %d-%d)\n",
           a->name, CRACK_ALPHA_MIN, CRACK_ALPHA_MAX,
           CRACK_MIN_LEN, CRACK_MAX_LEN);
    printf("Splitting the search space across %d threads, "
           "%" PRIu64 " candidates per work item.\n", nthreads,
           (uint64_t)CRACK_CHUNK);
    fflush(stdout);

    InitializeCriticalSection(&g_crack_cs);
    g_crack_found = 0;
    __sync_lock_test_and_set(&g_crack_attempts, 0);

    for (int len = CRACK_MIN_LEN; len <= CRACK_MAX_LEN && !g_crack_found; len++) {
        g_crack_len = (unsigned)len;
        __sync_lock_test_and_set(&g_crack_next, 0);
        printf("Trying length %d...\n", len);
        fflush(stdout);

        created = 0;
        for (int i = 0; i < nthreads; i++) {
            th[created] = CreateThread(NULL, 0, crack_worker, NULL, 0, NULL);
            if (th[created]) created++;
        }
        if (!created) {
            fprintf(stderr, "Failed to create worker threads.\n");
            break;
        }

        for (;;) {
            DWORD r = WaitForMultipleObjects((DWORD)created, th, TRUE, 1000);
            if (r != WAIT_TIMEOUT) break;
            printf("  ... tried %" PRId64 " candidates total (length %d)\n",
                   (int64_t)g_crack_attempts, len);
            fflush(stdout);
        }
        for (int i = 0; i < created; i++) CloseHandle(th[i]);

        if (g_crack_found) {
            printf("\n============================================\n");
            printf(" Match found\n");
            printf("============================================\n");
            printf(" Plain Text : \"%s\"\n", g_crack_plain);
            printf(" Algorithm  : %s\n", a->name);
            printf(" Hash       : %s\n", g_crack_target_hex);
            printf(" Threads    : %d\n", nthreads);
            printf(" Attempts   : %" PRId64 "\n", (int64_t)g_crack_attempts);
            printf("============================================\n");
            DeleteCriticalSection(&g_crack_cs);
            return 0;
        }
    }

    printf("\nNo match found (searched lengths %d-%d).\n",
           CRACK_MIN_LEN, CRACK_MAX_LEN);
    printf("Total attempts: %" PRId64 "\n", (int64_t)g_crack_attempts);
    DeleteCriticalSection(&g_crack_cs);
    return 1;
}

int main(void) {
    char line[32];

    wp_init();

    for (;;) {
        show_main_menu();
        if (!fgets(line, sizeof(line), stdin)) break;
        int c = (int)strtol(line, NULL, 10);
        if (c == 1) {
            if (mode_hash() < 0) {
                fprintf(stderr, "Failed to read input.\n");
                return 1;
            }
        } else if (c == 2) {
            if (mode_crack() < 0) {
                fprintf(stderr, "Failed to read input.\n");
                return 1;
            }
        } else if (c == 3) {
            printf("Goodbye.\n");
            return 0;
        } else {
            printf("Invalid choice, please enter 1, 2 or 3.\n");
        }
    }
    return 0;
}