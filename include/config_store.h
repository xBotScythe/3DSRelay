#ifndef CONFIG_STORE_H
#define CONFIG_STORE_H

#include <stdint.h>
#include <stddef.h>

#include <3ds.h>

static const uint32_t CONFIG_MAGIC_V4 = 0x43464734;
static const uint32_t CONFIG_MAGIC_V5 = 0x43464735;
static const uint32_t CONFIG_MAGIC_V6 = 0x43464736;
static const uint32_t CONFIG_KDF_ITERATIONS = 25000;

#pragma pack(push, 1)
// config stores hashes and encrypted identity material instead of raw secrets
struct config_t {
    uint32_t magic;
    uint32_t unlock_sequence_len;
    uint8_t unlock_hash[32];
    uint8_t unlock_salt[16];
    uint32_t kdf_iterations;
    uint8_t kdf_salt[16];
    uint8_t identity_nonce[12];
    uint8_t encrypted_identity_seed[32];
    uint8_t identity_mac[32];
    uint8_t identity_initialized;
    char user_alias[16];
    uint8_t reserved[15];
};
#pragma pack(pop)

extern config_t config;
extern bool system_unlocked;
extern int failed_unlock_attempts;
extern size_t unlock_input_index;

void save_config(const config_t& cfg);
bool load_config(config_t& cfg);
void initialize_default_config(config_t& config);

void hash_unlock_sequence(const uint32_t* seq, size_t len, uint8_t hash_out[32], const uint8_t* salt = 0, size_t salt_len = 0);
uint32_t extract_unlock_key(uint32_t keys_down);
void reset_unlock_input(void);
void process_unlock_input(uint32_t key, const config_t& cfg);

#endif
