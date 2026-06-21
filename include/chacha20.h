// chacha20.h
// lightweight chacha20 cipher for local payload encryption

#pragma once

#include <cstdint>
#include <cstddef>
#include "network.h"
#include "sha256.h"

// encrypts or decrypts a buffer using chacha20 stream cipher
void chacha20_crypt(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, const uint8_t* input, uint8_t* output, size_t len);

// fills a buffer with platform random bytes
void secure_random_bytes(uint8_t* buf, size_t len);
