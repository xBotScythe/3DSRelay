#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <stdint.h>
#include <stddef.h>
#include <string>
#include "network.h" // for packet_t

class PacketRingBuffer;
struct config_t;

#pragma pack(push, 1)
struct contact_t {
    char alias[16];
    uint8_t pk_box[32];
    bool active;
    bool confirmed;
};
#pragma pack(pop)

// contact list globals
extern contact_t contact_list[5];
extern int contact_count;
extern int selected_contact_idx;

// runtime derived keys held in ram
extern uint8_t static_pk_sign[32];
extern uint8_t static_sk_sign[64];
extern uint8_t static_pk_box[32];
extern uint8_t static_sk_box[32];
extern bool keys_derived;

extern const uint8_t dev_pk_sign[32];
extern const uint32_t CURRENT_APP_VERSION;

bool verify_update_manifest(const update_manifest_t& manifest);


bool derive_keys_from_passphrase(const char* alias, const char* passphrase, config_t& cfg);
void pbkdf2_hmac_sha256(const char* passphrase, const uint8_t* salt, size_t salt_len, uint32_t iterations, uint8_t out_key[32]);
std::string public_contact_card();
std::string public_key_fingerprint(const uint8_t public_key[32]);

void hex_to_bytes(const char* hex, uint8_t* bytes, size_t len);
std::string bytes_to_hex(const uint8_t* bytes, size_t len);

bool encrypt_message_packet(packet_t& packet, const char* plaintext_msg, const uint8_t recipient_pk_box[32], const uint8_t sender_sk_box[32]);
bool decrypt_message_packet(const packet_t& packet, char* plaintext_out, int max_len, char* sender_alias_out, int max_alias_len, const uint8_t sk_box[32]);

bool create_handshake_packet(packet_t& packet, const uint8_t recipient_pk_box[32], const char* user_alias, const uint8_t* my_pk_sign, const uint8_t* my_sk_sign);
bool decrypt_handshake_packet(const packet_t& packet, uint8_t sender_pk_box[32], char* sender_alias_out, int max_alias_len, const uint8_t sk_box[32]);

bool verify_broadcast_packet(const packet_t& packet, char* sender_alias_out, int max_alias_len, char* plaintext_out, int max_plain_len, uint8_t sender_pk_box_out[32]);
void sign_broadcast_data(uint8_t* payload, int data_len, const uint8_t sk_sign[64]);

bool add_contact_record(const char* alias, const char* key_or_card);
void wipe_runtime_secrets(PacketRingBuffer& buffer);

bool save_contacts_to_file();
bool load_contacts_from_file();

#endif
