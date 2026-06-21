// chacha20.cpp
// chacha20 stream cipher implementation

#include "chacha20.h"
#include <cstring>

#include <3ds.h>

#define CHACHA_ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static void chacha20_quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = CHACHA_ROTL(d, 16);
    c += d; b ^= c; b = CHACHA_ROTL(b, 12);
    a += b; d ^= a; d = CHACHA_ROTL(d, 8);
    c += d; b ^= c; b = CHACHA_ROTL(b, 7);
}

static void chacha20_block(const uint32_t key[8], const uint32_t nonce[3], uint32_t counter, uint32_t out[16]) {
    uint32_t state[16] = {
        0x61737865, 0x3320646e, 0x79622d32, 0x6b206574,
        key[0], key[1], key[2], key[3],
        key[4], key[5], key[6], key[7],
        counter, nonce[0], nonce[1], nonce[2]
    };

    uint32_t initial[16];
    std::memcpy(initial, state, sizeof(state));

    for (int i = 0; i < 10; ++i) {
        // column rounds
        chacha20_quarter_round(state[0], state[4], state[8], state[12]);
        chacha20_quarter_round(state[1], state[5], state[9], state[13]);
        chacha20_quarter_round(state[2], state[6], state[10], state[14]);
        chacha20_quarter_round(state[3], state[7], state[11], state[15]);
        // diagonal rounds
        chacha20_quarter_round(state[0], state[5], state[10], state[15]);
        chacha20_quarter_round(state[1], state[6], state[11], state[12]);
        chacha20_quarter_round(state[2], state[7], state[8], state[13]);
        chacha20_quarter_round(state[3], state[4], state[9], state[14]);
    }

    for (int i = 0; i < 16; ++i) {
        out[i] = state[i] + initial[i];
    }
}

void chacha20_crypt(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, const uint8_t* input, uint8_t* output, size_t len) {
    uint32_t key_words[8];
    uint32_t nonce_words[3];
    
    std::memcpy(key_words, key, 32);
    std::memcpy(nonce_words, nonce, 12);

    uint8_t keystream[64];
    uint32_t out[16];
    size_t i = 0;

    while (i < len) {
        chacha20_block(key_words, nonce_words, counter, out);
        std::memcpy(keystream, out, 64);
        counter++;

        size_t block_len = (len - i < 64) ? (len - i) : 64;
        for (size_t j = 0; j < block_len; ++j) {
            output[i + j] = input[i + j] ^ keystream[j];
        }
        i += block_len;
    }
}

