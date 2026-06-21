// config_store.cpp
// file storage configurations and unlock input pattern matching

#include "config_store.h"
#include "crypto_utils.h"
#include "sha256.h"
#include "chacha20.h"
#include <cstdio>
#include <cstring>

bool system_unlocked = false;
int failed_unlock_attempts = 0;

static bool all_zero(const uint8_t* data, size_t len) {
    uint8_t acc = 0;
    for (size_t i = 0; i < len; ++i) {
        acc |= data[i];
    }
    return acc == 0;
}

// select standard config path to prevent default devoptab crash on hardware
#define CONFIG_FILE_PATH "sdmc:/3ds/3dsrelay.cfg"

void save_config(const config_t& cfg) {
    config_t disk_copy;
    std::memcpy(&disk_copy, &cfg, sizeof(config_t));
    std::memset(disk_copy.user_alias, 0, sizeof(disk_copy.user_alias));
    std::FILE* f = std::fopen(CONFIG_FILE_PATH ".tmp", "wb");
    if (f) {
        std::fwrite(&disk_copy, sizeof(config_t), 1, f);
        std::fflush(f);
        std::fclose(f);
        std::remove(CONFIG_FILE_PATH);
        std::rename(CONFIG_FILE_PATH ".tmp", CONFIG_FILE_PATH);
    }
    std::memset(&disk_copy, 0, sizeof(disk_copy));
}

struct config_v4_t {
    uint32_t magic;
    uint32_t unlock_sequence_len;
    uint8_t unlock_hash[32];
};

bool load_config(config_t& cfg) {
    std::FILE* f = std::fopen(CONFIG_FILE_PATH, "rb");
    if (!f) {
        return false;
    }
    std::memset(&cfg, 0, sizeof(cfg));
    uint32_t magic = 0;
    if (std::fread(&magic, sizeof(magic), 1, f) != 1) {
        std::fclose(f);
        return false;
    }
    std::rewind(f);

    bool ok = false;
    if (magic == CONFIG_MAGIC_V6) {
        size_t read_bytes = std::fread(&cfg, sizeof(config_t), 1, f);
        ok = (read_bytes == 1 && cfg.unlock_sequence_len >= 1 && cfg.unlock_sequence_len <= 16);
    } else if (magic == CONFIG_MAGIC_V5) {
        size_t read_bytes = std::fread(&cfg, sizeof(config_t), 1, f);
        if (read_bytes == 1 && cfg.unlock_sequence_len >= 1 && cfg.unlock_sequence_len <= 16) {
            cfg.magic = CONFIG_MAGIC_V6;
            std::memset(cfg.user_alias, 0, sizeof(cfg.user_alias));
            ok = true;
        }
    } else if (magic == CONFIG_MAGIC_V4) {
        config_v4_t old_cfg;
        std::memset(&old_cfg, 0, sizeof(old_cfg));
        size_t read_bytes = std::fread(&old_cfg, sizeof(old_cfg), 1, f);
        if (read_bytes == 1 && old_cfg.unlock_sequence_len >= 1 && old_cfg.unlock_sequence_len <= 16) {
            cfg.magic = CONFIG_MAGIC_V6;
            cfg.unlock_sequence_len = old_cfg.unlock_sequence_len;
            std::memcpy(cfg.unlock_hash, old_cfg.unlock_hash, 32);
            cfg.kdf_iterations = CONFIG_KDF_ITERATIONS;
            std::memset(cfg.user_alias, 0, sizeof(cfg.user_alias));
            ok = true;
        }
    }
    std::fclose(f);
    return ok;
}

void hash_unlock_sequence(const uint32_t* seq, size_t len, uint8_t hash_out[32], const uint8_t* salt, size_t salt_len) {
    if (salt && salt_len > 0) {
        sha256_hash_t h = hmac_sha256(salt, salt_len, (const uint8_t*)seq, len * sizeof(uint32_t));
        std::memcpy(hash_out, h.bytes, 32);
    } else {
        sha256_hash_t h = sha256(seq, len * sizeof(uint32_t));
        std::memcpy(hash_out, h.bytes, 32);
    }
}

uint32_t unlock_input_buffer[16];
size_t unlock_input_index = 0;
static uint64_t last_keypress_time = 0;

static const uint32_t UNLOCK_KEY_MASK =
    KEY_DUP | KEY_DDOWN | KEY_DLEFT | KEY_DRIGHT | KEY_A | KEY_B | KEY_X | KEY_Y | KEY_L | KEY_R;

static uint64_t get_current_time_ms() {
    return osGetTime();
}

void reset_unlock_input(void) {
    unlock_input_index = 0;
    std::memset(unlock_input_buffer, 0, sizeof(unlock_input_buffer));
    last_keypress_time = 0;
}

uint32_t extract_unlock_key(uint32_t keys_down) {
    // native hardware edge detection filters inputs at system level
    // manual edge detection is omitted to avoid swallowing repeat button presses
    uint32_t masked = keys_down & UNLOCK_KEY_MASK;
    if (masked == 0) {
        return 0;
    }
    
    // Filter multi-direction D-pad inputs (diagonals).
    // D-pad directions should only be registered if there is a single clean direction set.
    uint32_t dpad_keys = masked & (KEY_DUP | KEY_DDOWN | KEY_DLEFT | KEY_DRIGHT);
    if (dpad_keys != 0 && (dpad_keys & (dpad_keys - 1)) != 0) {
        return 0;
    }

    // Take the lowest set bit to avoid swallowing keys on overlapping presses or emulator key overlap
    int bit_index = __builtin_ffs(masked);
    if (bit_index > 0) {
        return 1 << (bit_index - 1);
    }
    return 0;
}

void process_unlock_input(uint32_t key, const config_t& cfg) {
    if (key == 0) {
        return;
    }

    uint64_t now = get_current_time_ms();
    // 5-second inactivity timeout resets sequence index to discard stale inputs and allow slow/deliberate entry
    if (unlock_input_index > 0 && (now - last_keypress_time > 5000)) {
        reset_unlock_input();
    }
    last_keypress_time = now;

    unlock_input_buffer[unlock_input_index++] = key;

    if (unlock_input_index >= cfg.unlock_sequence_len) {
        uint8_t input_hash[32];
        bool salted = (cfg.magic == CONFIG_MAGIC_V5 || cfg.magic == CONFIG_MAGIC_V6) && !all_zero(cfg.unlock_salt, sizeof(cfg.unlock_salt));
        const uint8_t* salt = salted ? cfg.unlock_salt : 0;
        size_t salt_len = salted ? sizeof(cfg.unlock_salt) : 0;
        hash_unlock_sequence(unlock_input_buffer, cfg.unlock_sequence_len, input_hash, salt, salt_len);
        // constant-time comparison prevents side-channel timing leakage
        uint8_t diff = 0;
        for (int i = 0; i < 32; ++i) {
            diff |= input_hash[i] ^ cfg.unlock_hash[i];
        }
        if (diff == 0) {
            system_unlocked = true;
            failed_unlock_attempts = 0;
        } else {
            if (keys_derived) {
                failed_unlock_attempts++;
                if (failed_unlock_attempts >= 3) {
                    std::memset(static_sk_box, 0, 32);
                    std::memset(static_pk_box, 0, 32);
                    std::memset(static_sk_sign, 0, 64);
                    std::memset(static_pk_sign, 0, 32);
                    std::memset(contact_list, 0, sizeof(contact_list));
                    keys_derived = false;
                    failed_unlock_attempts = 0;
                }
            }
        }
        reset_unlock_input();
    } else if (unlock_input_index >= 16) {
        reset_unlock_input(); // prevent overflow
    }
}

void initialize_default_config(config_t& config) {
    std::memset(&config, 0, sizeof(config));
    config.magic = CONFIG_MAGIC_V6;
    config.unlock_sequence_len = 6;
    config.kdf_iterations = CONFIG_KDF_ITERATIONS;
    secure_random_bytes(config.unlock_salt, sizeof(config.unlock_salt));
    secure_random_bytes(config.kdf_salt, sizeof(config.kdf_salt));
    uint32_t default_seq[6] = {KEY_DUP, KEY_DDOWN, KEY_DUP, KEY_DDOWN, KEY_DLEFT, KEY_DRIGHT};
    hash_unlock_sequence(default_seq, 6, config.unlock_hash, config.unlock_salt, sizeof(config.unlock_salt));
    std::memset(default_seq, 0, sizeof(default_seq));
    save_config(config);
}
