#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <stdint.h>
#include <stddef.h>
#include <string>
#include "network.h" // for packet_t
#include "version.h" // CURRENT_APP_VERSION, format_app_version

class PacketRingBuffer;
struct config_t;

// contact trust tiers; private messaging requires verified or introduced
static const uint8_t CONTACT_UNVERIFIED = 0; // mesh-discovered, not messageable
static const uint8_t CONTACT_INTRODUCED = 1; // vouched by a verified contact
static const uint8_t CONTACT_VERIFIED   = 2; // scanned/added in person

#pragma pack(push, 1)
struct contact_t {
    char alias[16];
    uint8_t pk_box[32];
    uint8_t pk_sign[32];   // pinned signing key; zero until learned
    uint8_t trust;         // CONTACT_UNVERIFIED / INTRODUCED / VERIFIED
    char introducer[16];   // voucher alias for introduced contacts
    bool active;
    bool confirmed;
};
#pragma pack(pop)

// pending unsolicited handshake awaiting accept/reject; ram-only
struct incoming_request_t {
    char alias[16];
    uint8_t pk_box[32];
};

// contact list globals
extern contact_t contact_list[5];
extern int contact_count;
extern int selected_contact_idx;

// inbound handshake requests pending the user's decision
extern incoming_request_t incoming_requests[5];
extern int incoming_request_count;

// runtime derived keys held in ram
extern uint8_t static_pk_sign[32];
extern uint8_t static_sk_sign[64];
extern uint8_t static_pk_box[32];
extern uint8_t static_sk_box[32];
extern bool keys_derived;

// at-rest keys for local storage, derived from the identity seed with their
// own labels so the network box secret is never reused as a storage key
extern uint8_t atrest_enc[32];
extern uint8_t atrest_mac[32];

extern const uint8_t dev_pk_sign[32];

bool verify_update_manifest(const update_manifest_t& manifest);


bool derive_keys_from_passphrase(const char* alias, const char* passphrase, config_t& cfg);
void pbkdf2_hmac_sha256(const char* passphrase, const uint8_t* salt, size_t salt_len, uint32_t iterations, uint8_t out_key[32]);
std::string public_contact_card();
std::string public_key_fingerprint(const uint8_t public_key[32]);

// first byte of the compact binary contact card carried in the qr
static const uint8_t BIN_CARD_MAGIC = 0xB1;

// builds the binary contact card (magic, alias, box key, sign key, signature);
// returns bytes written or 0
size_t build_binary_contact_card(uint8_t* out, size_t out_cap);
// rebuilds the 3dsr2 text card from a scanned binary card for verification
bool binary_card_to_text(const uint8_t* in, size_t in_len, char* out, size_t out_cap);

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
// ram-only scrub; leaves the encrypted sd files intact so lock/exit keeps data
void scrub_runtime_secrets(PacketRingBuffer& buffer);

bool save_contacts_to_file();
bool load_contacts_from_file();

#endif
