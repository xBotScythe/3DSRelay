// crypto_utils.cpp
// cryptographic helper utilities and key derivation routines

#include "crypto_utils.h"
#include "config_store.h"
#include "chacha20.h"
#include "sha256.h"
#include "tweetnacl.h"
#include "smaz.h"
#include "ringbuffer.h"
#include <cstring>
#include <cstdlib>
#include <iomanip>
#include <sstream>

#include <3ds.h>
#include "ui_rendering.h"

contact_t contact_list[5] = {
    {"", {0}, false, false},
    {"", {0}, false, false},
    {"", {0}, false, false},
    {"", {0}, false, false},
    {"", {0}, false, false}
};
int contact_count = 0;
int selected_contact_idx = 0;

// unsolicited handshakes awaiting the user's accept/reject decision; ram-only,
// senders resend periodically so a missed request reappears
incoming_request_t incoming_requests[5] = {};
int incoming_request_count = 0;

// global key variables
uint8_t static_pk_sign[32];
uint8_t static_sk_sign[64];
uint8_t static_pk_box[32];
uint8_t static_sk_box[32];
bool keys_derived = false;

bool use_deterministic_random = false;
uint8_t deterministic_random_seed[32] = {0};

void secure_random_bytes(uint8_t* buf, size_t len) {
    // request random bytes from system hardware generator with fallback to linear congruential hash
    Result rc = psInit();
    if (R_SUCCEEDED(rc)) {
        PS_GenerateRandomBytes(buf, len);
        psExit();
    } else {
        static uint32_t seed = 0x12345678;
        for (unsigned long long i = 0; i < len; ++i) {
            seed = seed * 1664525u + 1013904223u;
            buf[i] = (unsigned char)((seed ^ (uint32_t)osGetTime()) & 0xFF);
        }
    }
}

extern "C" void randombytes(unsigned char* buf, unsigned long long len) {
    if (use_deterministic_random && len == 32) {
        std::memcpy(buf, deterministic_random_seed, 32);
        return;
    }
    secure_random_bytes(buf, (size_t)len);
}

static bool all_zero_local(const uint8_t* data, size_t len) {
    uint8_t acc = 0;
    for (size_t i = 0; i < len; ++i) {
        acc |= data[i];
    }
    return acc == 0;
}

void pbkdf2_hmac_sha256(const char* passphrase, const uint8_t* salt, size_t salt_len, uint32_t iterations, uint8_t out_key[32]) {
    if (iterations == 0) {
        iterations = 1;
    }

    uint8_t block_input[80];
    size_t use_salt_len = salt_len;
    if (use_salt_len > sizeof(block_input) - 4) {
        use_salt_len = sizeof(block_input) - 4;
    }
    std::memcpy(block_input, salt, use_salt_len);
    block_input[use_salt_len + 0] = 0;
    block_input[use_salt_len + 1] = 0;
    block_input[use_salt_len + 2] = 0;
    block_input[use_salt_len + 3] = 1;

    sha256_hash_t u = hmac_sha256(
        (const uint8_t*)passphrase,
        std::strlen(passphrase),
        block_input,
        use_salt_len + 4
    );
    std::memcpy(out_key, u.bytes, 32);

    for (uint32_t iter = 1; iter < iterations; ++iter) {
        u = hmac_sha256((const uint8_t*)passphrase, std::strlen(passphrase), u.bytes, 32);
        for (int i = 0; i < 32; ++i) {
            out_key[i] ^= u.bytes[i];
        }
    }

    std::memset(block_input, 0, sizeof(block_input));
    std::memset(&u, 0, sizeof(u));
}

static void derive_keypairs_from_identity_seed(const uint8_t identity_seed[32]) {
    bool orig_use_det = use_deterministic_random;
    uint8_t orig_seed[32];
    std::memcpy(orig_seed, deterministic_random_seed, 32);

    sha256_hash_t sign_seed = hmac_sha256((const uint8_t*)"3dsrelay-sign-seed", 18, identity_seed, 32);
    use_deterministic_random = true;
    std::memcpy(deterministic_random_seed, sign_seed.bytes, 32);
    crypto_sign_keypair(static_pk_sign, static_sk_sign);

    sha256_hash_t box_seed = hmac_sha256((const uint8_t*)"3dsrelay-box-seed", 17, identity_seed, 32);
    std::memcpy(deterministic_random_seed, box_seed.bytes, 32);
    crypto_box_keypair(static_pk_box, static_sk_box);

    use_deterministic_random = orig_use_det;
    std::memcpy(deterministic_random_seed, orig_seed, 32);
    std::memset(&sign_seed, 0, sizeof(sign_seed));
    std::memset(&box_seed, 0, sizeof(box_seed));
}

void hex_to_bytes(const char* hex, uint8_t* bytes, size_t len) {
    std::memset(bytes, 0, len);
    size_t hex_len = std::strlen(hex);
    for (size_t i = 0; i < len && i * 2 + 1 < hex_len; ++i) {
        char byte_chars[3] = { hex[i * 2], hex[i * 2 + 1], '\0' };
        bytes[i] = (uint8_t)std::strtol(byte_chars, NULL, 16);
    }
}

std::string bytes_to_hex(const uint8_t* bytes, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << (int)bytes[i];
    }
    return ss.str();
}

bool derive_keys_from_passphrase(const char* alias, const char* passphrase, config_t& cfg) {
    if (!alias || std::strlen(alias) == 0 || !passphrase || std::strlen(passphrase) == 0) {
        return false;
    }

    cfg.magic = CONFIG_MAGIC_V6;
    if (cfg.kdf_iterations == 0) {
        cfg.kdf_iterations = CONFIG_KDF_ITERATIONS;
    }
    if (all_zero_local(cfg.kdf_salt, sizeof(cfg.kdf_salt))) {
        secure_random_bytes(cfg.kdf_salt, sizeof(cfg.kdf_salt));
    }

    // alias is concatenated into the kdf input so the identity is
    // cryptographically bound to it; changing the alias produces
    // different keys and the mac check will reject
    char combined[96];
    std::snprintf(combined, sizeof(combined), "%s:%s", alias, passphrase);

    uint8_t kdf_key[32];
    pbkdf2_hmac_sha256(combined, cfg.kdf_salt, sizeof(cfg.kdf_salt), cfg.kdf_iterations, kdf_key);
    std::memset(combined, 0, sizeof(combined));

    uint8_t identity_seed[32];
    if (cfg.identity_initialized) {
        uint8_t mac_input[44];
        std::memcpy(mac_input, cfg.identity_nonce, 12);
        std::memcpy(mac_input + 12, cfg.encrypted_identity_seed, 32);
        sha256_hash_t mac = hmac_sha256(kdf_key, 32, mac_input, sizeof(mac_input));
        uint8_t diff = 0;
        for (int i = 0; i < 32; ++i) {
            diff |= mac.bytes[i] ^ cfg.identity_mac[i];
        }
        std::memset(&mac, 0, sizeof(mac));
        std::memset(mac_input, 0, sizeof(mac_input));
        if (diff != 0) {
            std::memset(kdf_key, 0, sizeof(kdf_key));
            return false;
        }
        chacha20_crypt(kdf_key, cfg.identity_nonce, 0, cfg.encrypted_identity_seed, identity_seed, 32);
    } else {
        secure_random_bytes(identity_seed, sizeof(identity_seed));
        secure_random_bytes(cfg.identity_nonce, sizeof(cfg.identity_nonce));
        chacha20_crypt(kdf_key, cfg.identity_nonce, 0, identity_seed, cfg.encrypted_identity_seed, 32);

        uint8_t mac_input[44];
        std::memcpy(mac_input, cfg.identity_nonce, 12);
        std::memcpy(mac_input + 12, cfg.encrypted_identity_seed, 32);
        sha256_hash_t mac = hmac_sha256(kdf_key, 32, mac_input, sizeof(mac_input));
        std::memcpy(cfg.identity_mac, mac.bytes, 32);
        cfg.identity_initialized = 1;
        std::memset(&mac, 0, sizeof(mac));
        std::memset(mac_input, 0, sizeof(mac_input));
        save_config(cfg);
    }

    derive_keypairs_from_identity_seed(identity_seed);
    std::memset(identity_seed, 0, sizeof(identity_seed));
    std::memset(kdf_key, 0, sizeof(kdf_key));
    keys_derived = true;
    return true;
}

std::string public_key_fingerprint(const uint8_t public_key[32]) {
    sha256_hash_t fp = sha256(public_key, 32);
    std::string hex = bytes_to_hex(fp.bytes, 8);
    std::memset(&fp, 0, sizeof(fp));
    return hex.substr(0, 4) + "-" + hex.substr(4, 4) + "-" + hex.substr(8, 4) + "-" + hex.substr(12, 4);
}

std::string public_contact_card() {
    int alias_len = std::strlen(config.user_alias);
    int data_len = alias_len + 32;
    uint8_t data[32 + 32];
    std::memcpy(data, config.user_alias, alias_len);
    std::memcpy(data + alias_len, static_pk_box, 32);

    uint8_t sm[64 + 32 + 32];
    unsigned long long smlen = 0;
    crypto_sign(sm, &smlen, data, data_len, static_sk_sign);

    uint8_t sig[64];
    std::memcpy(sig, sm, 64);

    return std::string("3DSR2:") + config.user_alias + ":" + bytes_to_hex(static_pk_box, 32) + ":" + bytes_to_hex(static_pk_sign, 32) + ":" + bytes_to_hex(sig, 64);
}

bool encrypt_message_packet(packet_t& packet, const char* plaintext_msg, const uint8_t recipient_pk_box[32], const uint8_t sender_sk_box[32]) {
    char compressed[256];
    std::memset(compressed, 0, sizeof(compressed));
    int comp_len = smaz_compress((char*)plaintext_msg, std::strlen(plaintext_msg), compressed, sizeof(compressed));
    if (comp_len < 0 || (size_t)comp_len > PLAINTEXT_PAYLOAD_SIZE) {
        return false;
    }
    
    uint8_t ephemeral_sk[32];
    crypto_box_keypair(packet.ephemeral_pk, ephemeral_sk);
    
    uint8_t k_ephemeral[32];
    crypto_box_beforenm(k_ephemeral, recipient_pk_box, ephemeral_sk);
    
    uint8_t k_static[32];
    crypto_box_beforenm(k_static, recipient_pk_box, sender_sk_box);
    
    sha256_hash_t combined = hmac_sha256(k_static, 32, k_ephemeral, 32);
    
    uint8_t padded_plain[32 + PLAINTEXT_PAYLOAD_SIZE] = {0};
    uint8_t padded_cipher[32 + PLAINTEXT_PAYLOAD_SIZE] = {0};
    std::memcpy(padded_plain + 32, compressed, comp_len);
    
    uint8_t box_nonce[24];
    std::memcpy(box_nonce, packet.ephemeral_pk, 24);
    
    int res = crypto_box_afternm(padded_cipher, padded_plain, 32 + PLAINTEXT_PAYLOAD_SIZE, box_nonce, combined.bytes);
    
    std::memset(ephemeral_sk, 0, 32);
    std::memset(k_ephemeral, 0, 32);
    std::memset(k_static, 0, 32);
    std::memset(&combined, 0, sizeof(combined));
    
    if (res != 0) {
        return false;
    }
    
    std::memcpy(packet.encrypted_payload, padded_cipher + 16, ENCRYPTED_PAYLOAD_SIZE);
    return true;
}

bool decrypt_message_packet(const packet_t& packet, char* plaintext_out, int max_len, char* sender_alias_out, int max_alias_len, const uint8_t sk_box[32]) {
    uint8_t padded_cipher[32 + PLAINTEXT_PAYLOAD_SIZE] = {0};
    std::memcpy(padded_cipher + 16, packet.encrypted_payload, ENCRYPTED_PAYLOAD_SIZE);
    
    uint8_t box_nonce[24];
    std::memcpy(box_nonce, packet.ephemeral_pk, 24);
    
    for (int i = 0; i < 5; ++i) {
        if (!contact_list[i].active) continue;
        
        uint8_t k_ephemeral[32];
        crypto_box_beforenm(k_ephemeral, packet.ephemeral_pk, sk_box);
        
        uint8_t k_static[32];
        crypto_box_beforenm(k_static, contact_list[i].pk_box, sk_box);
        
        sha256_hash_t combined = hmac_sha256(k_static, 32, k_ephemeral, 32);
        
        uint8_t padded_plain[32 + PLAINTEXT_PAYLOAD_SIZE] = {0};
        int res = crypto_box_open_afternm(padded_plain, padded_cipher, 32 + PLAINTEXT_PAYLOAD_SIZE, box_nonce, combined.bytes);
        
        std::memset(k_ephemeral, 0, 32);
        std::memset(k_static, 0, 32);
        std::memset(&combined, 0, sizeof(combined));
        
        if (res == 0) {
            char compressed[PLAINTEXT_PAYLOAD_SIZE];
            std::memcpy(compressed, padded_plain + 32, PLAINTEXT_PAYLOAD_SIZE);
            
            int decomp_len = smaz_decompress(compressed, PLAINTEXT_PAYLOAD_SIZE, plaintext_out, max_len - 1);
            if (decomp_len >= 0) {
                plaintext_out[decomp_len] = '\0';
                std::strncpy(sender_alias_out, contact_list[i].alias, max_alias_len - 1);
                sender_alias_out[max_alias_len - 1] = '\0';
                return true;
            }
        }
    }
    return false;
}

#define CONTACTS_FILE_PATH "sdmc:/3ds/3dsrelay.contacts"

bool create_handshake_packet(packet_t& packet, const uint8_t recipient_pk_box[32], const char* user_alias, const uint8_t* my_pk_sign, const uint8_t* my_sk_sign) {
    uint8_t ephemeral_sk[32];
    crypto_box_keypair(packet.ephemeral_pk, ephemeral_sk);
    
    uint8_t k_ephemeral[32];
    crypto_box_beforenm(k_ephemeral, recipient_pk_box, ephemeral_sk);
    
    uint8_t plaintext[152] = {0};
    plaintext[0] = 'H';
    plaintext[1] = 'S';
    std::memcpy(plaintext + 2, static_pk_box, 32);
    std::strncpy((char*)(plaintext + 34), user_alias, 15);
    plaintext[49] = '\0';
    std::memcpy(plaintext + 50, my_pk_sign, 32);
    
    uint8_t sig[64];
    uint8_t sm[64 + 50];
    unsigned long long smlen = 0;
    crypto_sign(sm, &smlen, plaintext, 50, my_sk_sign);
    std::memcpy(sig, sm, 64);
    std::memcpy(plaintext + 82, sig, 64);
    
    uint8_t padded_plain[32 + 152] = {0};
    uint8_t padded_cipher[32 + 152] = {0};
    std::memcpy(padded_plain + 32, plaintext, 152);
    
    uint8_t box_nonce[24];
    std::memcpy(box_nonce, packet.ephemeral_pk, 24);
    
    int res = crypto_box_afternm(padded_cipher, padded_plain, 32 + 152, box_nonce, k_ephemeral);
    
    std::memset(ephemeral_sk, 0, sizeof(ephemeral_sk));
    std::memset(k_ephemeral, 0, sizeof(k_ephemeral));
    
    if (res != 0) {
        return false;
    }
    
    std::memcpy(packet.encrypted_payload, padded_cipher + 16, ENCRYPTED_PAYLOAD_SIZE);
    return true;
}

bool decrypt_handshake_packet(const packet_t& packet, uint8_t sender_pk_box[32], char* sender_alias_out, int max_alias_len, const uint8_t sk_box[32]) {
    uint8_t k_ephemeral[32];
    crypto_box_beforenm(k_ephemeral, packet.ephemeral_pk, sk_box);
    
    uint8_t padded_cipher[32 + 152] = {0};
    std::memcpy(padded_cipher + 16, packet.encrypted_payload, ENCRYPTED_PAYLOAD_SIZE);
    
    uint8_t box_nonce[24];
    std::memcpy(box_nonce, packet.ephemeral_pk, 24);
    
    uint8_t padded_plain[32 + 152] = {0};
    int res = crypto_box_open_afternm(padded_plain, padded_cipher, 32 + 152, box_nonce, k_ephemeral);
    
    std::memset(k_ephemeral, 0, sizeof(k_ephemeral));
    
    if (res != 0) {
        return false;
    }
    
    uint8_t plaintext[152];
    std::memcpy(plaintext, padded_plain + 32, 152);
    
    if (plaintext[0] != 'H' || plaintext[1] != 'S') {
        return false;
    }
    
    const uint8_t* sender_pk_sign = plaintext + 50;
    const uint8_t* sig = plaintext + 82;
    
    uint8_t sm[64 + 50];
    std::memcpy(sm, sig, 64);
    std::memcpy(sm + 64, plaintext, 50);
    
    uint8_t m[64 + 50];
    unsigned long long mlen = 0;
    int sig_res = crypto_sign_open(m, &mlen, sm, 64 + 50, sender_pk_sign);
    if (sig_res != 0 || mlen != 50) {
        return false;
    }
    
    std::memcpy(sender_pk_box, plaintext + 2, 32);
    std::strncpy(sender_alias_out, (const char*)(plaintext + 34), max_alias_len - 1);
    sender_alias_out[max_alias_len - 1] = '\0';
    return true;
}

bool verify_broadcast_packet(const packet_t& packet, char* sender_alias_out, int max_alias_len, char* plaintext_out, int max_plain_len, uint8_t sender_pk_box_out[32]) {
    if (packet.ver != 3) {
        return false;
    }
    const uint8_t* payload = packet.encrypted_payload;
    if (payload[0] != 'B' || payload[1] != 'C') {
        return false;
    }
    
    const uint8_t* sender_pk_sign = packet.ephemeral_pk;
    
    uint8_t sig[64];
    std::memcpy(sig, payload + 50, 64);
    
    uint8_t msg_len = payload[114];
    if (msg_len > 53) {
        return false;
    }
    
    uint8_t sm[64 + 115 + 53];
    std::memcpy(sm, sig, 64);
    std::memcpy(sm + 64, payload, 50);
    std::memcpy(sm + 64 + 50, payload + 114, 1 + msg_len);
    
    uint8_t m[64 + 115 + 53];
    unsigned long long mlen = 0;
    int res = crypto_sign_open(m, &mlen, sm, 64 + 50 + 1 + msg_len, sender_pk_sign);
    if (res != 0 || mlen != (unsigned long long)(50 + 1 + msg_len)) {
        return false;
    }
    
    std::memcpy(sender_pk_box_out, payload + 2, 32);
    std::strncpy(sender_alias_out, (const char*)(payload + 34), max_alias_len - 1);
    sender_alias_out[max_alias_len - 1] = '\0';
    
    int decomp_len = smaz_decompress((char*)(payload + 115), msg_len, plaintext_out, max_plain_len - 1);
    if (decomp_len < 0) {
        return false;
    }
    plaintext_out[decomp_len] = '\0';
    return true;
}

void sign_broadcast_data(uint8_t* payload, int data_len, const uint8_t sk_sign[64]) {
    uint8_t data_to_sign[115 + 53];
    std::memcpy(data_to_sign, payload, 50);
    std::memcpy(data_to_sign + 50, payload + 114, data_len - 114);
    
    uint8_t sm[64 + 115 + 53];
    unsigned long long smlen = 0;
    crypto_sign(sm, &smlen, data_to_sign, 50 + (data_len - 114), sk_sign);
    
    std::memcpy(payload + 50, sm, 64);
}

bool save_contacts_to_file() {
    if (!keys_derived) {
        return false;
    }
    std::FILE* f = std::fopen(CONTACTS_FILE_PATH ".tmp", "wb");
    if (!f) {
        return false;
    }

    uint8_t plaintext[4 + 250];
    std::memcpy(plaintext, &contact_count, 4);
    std::memcpy(plaintext + 4, contact_list, 250);

    uint8_t nonce[12];
    secure_random_bytes(nonce, 12);

    uint8_t ciphertext[4 + 250];
    chacha20_crypt(static_sk_box, nonce, 0, plaintext, ciphertext, sizeof(ciphertext));

    uint8_t mac_input[12 + sizeof(ciphertext)];
    std::memcpy(mac_input, nonce, 12);
    std::memcpy(mac_input + 12, ciphertext, sizeof(ciphertext));
    sha256_hash_t mac = hmac_sha256(static_sk_box, 32, mac_input, sizeof(mac_input));

    std::fwrite(nonce, 12, 1, f);
    std::fwrite(mac.bytes, 32, 1, f);
    std::fwrite(ciphertext, sizeof(ciphertext), 1, f);
    std::fflush(f);
    std::fclose(f);
    std::rename(CONTACTS_FILE_PATH ".tmp", CONTACTS_FILE_PATH);

    std::memset(plaintext, 0, sizeof(plaintext));
    std::memset(ciphertext, 0, sizeof(ciphertext));
    std::memset(mac_input, 0, sizeof(mac_input));
    return true;
}

bool load_contacts_from_file() {
    if (!keys_derived) {
        return false;
    }
    std::FILE* f = std::fopen(CONTACTS_FILE_PATH, "rb");
    if (!f) {
        return false;
    }
    
    uint8_t nonce[12];
    uint8_t mac_read[32];
    uint8_t ciphertext[4 + 250];
    
    if (std::fread(nonce, 12, 1, f) != 1 ||
        std::fread(mac_read, 32, 1, f) != 1 ||
        std::fread(ciphertext, sizeof(ciphertext), 1, f) != 1) {
        std::fclose(f);
        return false;
    }
    std::fclose(f);
    
    uint8_t mac_input[12 + sizeof(ciphertext)];
    std::memcpy(mac_input, nonce, 12);
    std::memcpy(mac_input + 12, ciphertext, sizeof(ciphertext));
    sha256_hash_t mac = hmac_sha256(static_sk_box, 32, mac_input, sizeof(mac_input));
    
    uint8_t diff = 0;
    for (int i = 0; i < 32; ++i) {
        diff |= mac.bytes[i] ^ mac_read[i];
    }
    std::memset(&mac, 0, sizeof(mac));
    std::memset(mac_input, 0, sizeof(mac_input));
    
    if (diff != 0) {
        return false;
    }
    
    uint8_t plaintext[4 + 250];
    chacha20_crypt(static_sk_box, nonce, 0, ciphertext, plaintext, sizeof(plaintext));
    
    std::memcpy(&contact_count, plaintext, 4);
    std::memcpy(contact_list, plaintext + 4, 245);
    std::memset(plaintext, 0, sizeof(plaintext));
    return true;
}

const uint8_t dev_pk_sign[32] = {
    0xde, 0x42, 0x04, 0x38, 0xaf, 0xf5, 0x53, 0x6b, 0x4f, 0x12, 0x20, 0x71, 0x57, 0x88, 0xd9, 0x1f,
    0xfe, 0x6d, 0x93, 0xda, 0xe8, 0x61, 0x39, 0x0f, 0x8d, 0xc5, 0x71, 0xda, 0x91, 0xf9, 0x0f, 0x4d
};

const uint32_t CURRENT_APP_VERSION = 220; // v2.2.0

bool verify_update_manifest(const update_manifest_t& manifest) {
    if (manifest.magic != 0x55504434) {
        return false;
    }
    const size_t msg_len = 4 + 4 + 32; // version, file_size, file_sha256
    uint8_t sm[64 + msg_len];
    std::memcpy(sm, manifest.signature, 64);
    size_t off = 64;
    std::memcpy(sm + off, &manifest.version, 4); off += 4;
    std::memcpy(sm + off, &manifest.file_size, 4); off += 4;
    std::memcpy(sm + off, manifest.file_sha256, 32); off += 32;

    uint8_t m[64 + msg_len];
    unsigned long long mlen = 0;
    int res = crypto_sign_open(m, &mlen, sm, sizeof(sm), dev_pk_sign);
    return (res == 0 && mlen == msg_len);
}

void wipe_runtime_secrets(PacketRingBuffer& buffer) {
    buffer.clear();
    clear_decryption_cache();
    buffer.delete_store_file("sdmc:/3ds/3dsrelay.packets");
    std::remove("sdmc:/3ds/3dsrelay.contacts");
    std::memset(static_sk_box, 0, 32);
    std::memset(static_pk_box, 0, 32);
    std::memset(static_sk_sign, 0, 64);
    std::memset(static_pk_sign, 0, 32);
    std::memset(contact_list, 0, sizeof(contact_list));
    contact_count = 0;
    selected_contact_idx = 0;
    keys_derived = false;
}

static bool is_valid_hex_key(const char* hex) {
    if (!hex || std::strlen(hex) != 64) {
        return false;
    }
    for (int i = 0; i < 64; ++i) {
        char c = hex[i];
        bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!ok) {
            return false;
        }
    }
    return true;
}

bool add_contact_record(const char* alias, const char* key_or_card) {
    if (!alias || !key_or_card || std::strlen(alias) == 0) {
        return false;
    }
    const char* key_hex = key_or_card;
    if (std::strncmp(key_or_card, "3DSR1:", 6) == 0) {
        key_hex = key_or_card + 6;
    }
    
    char parsed_alias[32] = "";
    char pk_box_hex[65] = "";
    char pk_sign_hex[65] = "";
    char sig_hex[129] = "";
    
    if (std::strncmp(key_or_card, "3DSR2:", 6) == 0) {
        const char* p = key_or_card + 6;
        const char* next_colon = std::strchr(p, ':');
        if (next_colon) {
            int alias_len = next_colon - p;
            if (alias_len > 0 && alias_len < 32) {
                std::memcpy(parsed_alias, p, alias_len);
                parsed_alias[alias_len] = '\0';
            }
            p = next_colon + 1;
            next_colon = std::strchr(p, ':');
            if (next_colon) {
                int pk_len = next_colon - p;
                if (pk_len == 64) {
                    std::memcpy(pk_box_hex, p, 64);
                    pk_box_hex[64] = '\0';
                }
                p = next_colon + 1;
                next_colon = std::strchr(p, ':');
                if (next_colon) {
                    int sign_len = next_colon - p;
                    if (sign_len == 64) {
                        std::memcpy(pk_sign_hex, p, 64);
                        pk_sign_hex[64] = '\0';
                    }
                    p = next_colon + 1;
                    std::strncpy(sig_hex, p, sizeof(sig_hex) - 1);
                    sig_hex[sizeof(sig_hex) - 1] = '\0';
                }
            }
        }
        
        if (parsed_alias[0] != '\0' && pk_box_hex[0] != '\0' && pk_sign_hex[0] != '\0' && sig_hex[0] != '\0') {
            uint8_t pk_box[32];
            hex_to_bytes(pk_box_hex, pk_box, 32);
            uint8_t pk_sign[32];
            hex_to_bytes(pk_sign_hex, pk_sign, 32);
            uint8_t sig[64];
            hex_to_bytes(sig_hex, sig, 64);
            
            int p_alias_len = std::strlen(parsed_alias);
            int data_len = p_alias_len + 32;
            uint8_t sm[64 + 32 + 32];
            std::memcpy(sm, sig, 64);
            std::memcpy(sm + 64, parsed_alias, p_alias_len);
            std::memcpy(sm + 64 + p_alias_len, pk_box, 32);
            
            uint8_t m[64 + 32 + 32];
            unsigned long long mlen = 0;
            if (crypto_sign_open(m, &mlen, sm, 64 + data_len, pk_sign) == 0 && mlen == (unsigned long long)data_len) {
                alias = parsed_alias;
                key_hex = pk_box_hex;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }
    
    if (!is_valid_hex_key(key_hex)) {
        return false;
    }
    
    uint8_t pk[32];
    hex_to_bytes(key_hex, pk, 32);
    
    // alias is permanently bound to this pubkey; a second add with the same key
    // is silently accepted but never overwrites the stored alias, preventing
    // impersonation even if an attacker obtains the same raw public key
    for (int i = 0; i < contact_count; ++i) {
        if (contact_list[i].active && std::memcmp(contact_list[i].pk_box, pk, 32) == 0) {
            std::memset(pk, 0, sizeof(pk));
            return true;
        }
    }
    
    int target_slot = -1;
    if (contact_count < 5) {
        target_slot = contact_count;
        contact_count++;
    } else {
        target_slot = 4;
    }
    if (target_slot < 0) {
        std::memset(pk, 0, sizeof(pk));
        return false;
    }
    
    std::strncpy(contact_list[target_slot].alias, alias, sizeof(contact_list[target_slot].alias) - 1);
    contact_list[target_slot].alias[sizeof(contact_list[target_slot].alias) - 1] = '\0';
    std::memcpy(contact_list[target_slot].pk_box, pk, 32);
    contact_list[target_slot].active = true;
    contact_list[target_slot].confirmed = false;
    if (contact_count == 1) {
        selected_contact_idx = target_slot;
    }
    std::memset(pk, 0, sizeof(pk));
    
    save_contacts_to_file();
    return true;
}


