// sha256.cpp
// self-contained sha256 implementation

#include "sha256.h"
#include <cstring>

// helper macros for sha256 processing
#define SHA256_ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define rotr(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

#define choice(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define majority(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define sig0(x) (rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22))
#define sig1(x) (rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25))
#define sub0(x) (rotr(x, 7) ^ rotr(x, 18) ^ ((x) >> 3))
#define sub1(x) (rotr(x, 17) ^ rotr(x, 19) ^ ((x) >> 10))

static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


static void sha256_transform(uint32_t state[8], const uint8_t data[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    uint32_t w[64];

    for (int i = 0; i < 16; ++i) {
        w[i] = ((uint32_t)data[i * 4] << 24) |
               ((uint32_t)data[i * 4 + 1] << 16) |
               ((uint32_t)data[i * 4 + 2] << 8) |
               ((uint32_t)data[i * 4 + 3]);
    }

    for (int i = 16; i < 64; ++i) {
        w[i] = sub1(w[i - 2]) + w[i - 7] + sub0(w[i - 15]) + w[i - 16];
    }

    for (int i = 0; i < 64; ++i) {
        uint32_t t1 = h + sig1(e) + choice(e, f, g) + k[i] + w[i];
        uint32_t t2 = sig0(a) + majority(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
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

void sha256_init(sha256_ctx* ctx) {
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

void sha256_update(sha256_ctx* ctx, const uint8_t* data, size_t len) {
    size_t index = (size_t)((ctx->count >> 3) & 63);
    ctx->count += (uint64_t)len << 3;
    size_t part_len = 64 - index;
    size_t i = 0;

    if (len >= part_len) {
        std::memcpy(&ctx->buffer[index], data, part_len);
        sha256_transform(ctx->state, ctx->buffer);
        for (i = part_len; i + 63 < len; i += 64) {
            sha256_transform(ctx->state, &data[i]);
        }
        index = 0;
    }

    if (i < len) {
        std::memcpy(&ctx->buffer[index], &data[i], len - i);
    }
}

void sha256_final(sha256_ctx* ctx, uint8_t hash[32]) {
    uint8_t final_count[8];
    for (int i = 0; i < 8; ++i) {
        final_count[i] = (uint8_t)(ctx->count >> ((7 - i) * 8));
    }

    uint8_t pad[64];
    std::memset(pad, 0, 64);
    pad[0] = 0x80;

    size_t index = (size_t)((ctx->count >> 3) & 63);
    size_t pad_len = (index < 56) ? (56 - index) : (120 - index);

    sha256_update(ctx, pad, pad_len);
    sha256_update(ctx, final_count, 8);

    for (int i = 0; i < 8; ++i) {
        hash[i * 4]     = (uint8_t)(ctx->state[i] >> 24);
        hash[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        hash[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        hash[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

sha256_hash_t sha256(const void* data, size_t len) {
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t*)data, len);
    sha256_hash_t result;
    sha256_final(&ctx, result.bytes);
    return result;
}

sha256_hash_t hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len) {
    uint8_t k_prime[64];
    std::memset(k_prime, 0, 64);

    if (key_len > 64) {
        sha256_hash_t key_hash = sha256(key, key_len);
        std::memcpy(k_prime, key_hash.bytes, 32);
    } else {
        std::memcpy(k_prime, key, key_len);
    }

    uint8_t ipad_key[64], opad_key[64];
    for (int i = 0; i < 64; ++i) {
        ipad_key[i] = k_prime[i] ^ 0x36;
        opad_key[i] = k_prime[i] ^ 0x5c;
    }

    // inner hash
    sha256_ctx inner_ctx;
    sha256_init(&inner_ctx);
    sha256_update(&inner_ctx, ipad_key, 64);
    sha256_update(&inner_ctx, data, data_len);
    uint8_t inner_hash[32];
    sha256_final(&inner_ctx, inner_hash);

    // outer hash
    sha256_ctx outer_ctx;
    sha256_init(&outer_ctx);
    sha256_update(&outer_ctx, opad_key, 64);
    sha256_update(&outer_ctx, inner_hash, 32);
    sha256_hash_t result;
    sha256_final(&outer_ctx, result.bytes);

    // zero sensitive intermediates
    std::memset(k_prime, 0, 64);
    std::memset(ipad_key, 0, 64);
    std::memset(opad_key, 0, 64);
    std::memset(inner_hash, 0, 32);

    return result;
}
