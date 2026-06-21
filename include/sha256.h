// sha256.h
// self-contained sha256 implementation for proof-of-work validation

#pragma once

#include <cstdint>
#include <cstddef>

struct sha256_hash_t {
    uint8_t bytes[32];
};

struct sha256_ctx {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];
};

void sha256_init(sha256_ctx* ctx);
void sha256_update(sha256_ctx* ctx, const uint8_t* data, size_t len);
void sha256_final(sha256_ctx* ctx, uint8_t hash[32]);

// computes sha256 hash of a buffer
sha256_hash_t sha256(const void* data, size_t len);

// computes hmac-sha256 of data using the given key
sha256_hash_t hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len);
