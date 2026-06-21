// network.h
// abstract communication interface layout
// standardizes data pipes across test environments

#pragma once

#include <cstddef>
#include <3ds.h>

static const size_t PLAINTEXT_PAYLOAD_SIZE = 152;
static const size_t ENCRYPTED_PAYLOAD_SIZE = 16 + PLAINTEXT_PAYLOAD_SIZE; // 168

// fixed structure for localized packet frames
// packed for consistent wire format across compilers
#pragma pack(push, 1)
struct packet_t {
    uint8_t ver;
    uint8_t ttl;
    uint32_t nonce;        // proof-of-work nonce
    uint8_t ephemeral_pk[32]; // ephemeral public key for trial decryption
    uint8_t encrypted_payload[ENCRYPTED_PAYLOAD_SIZE]; // 16-byte Poly1305 MAC + 152-byte Smaz payload
};

struct update_manifest_t {
    uint32_t magic;         // 0x55504434 ('UPD4')
    uint32_t version;       // app version
    uint32_t file_size;     // size of CIA payload
    uint8_t file_sha256[32];
    uint8_t signature[64];  // ed25519 signature of (version, file_size, file_sha256)
};

struct update_packet_t {
    uint8_t type;         // 0 = request block, 1 = data block, 2 = cancel/eof, 3 = batch request (block_index=start, length=count)
    uint32_t block_index;
    uint32_t length;
    uint8_t payload[480];
};
#pragma pack(pop)

// payload bytes carried per data block; wire format kept stable for cross-version transfers
static const uint32_t UPDATE_BLOCK_SIZE = 480;
// blocks a seeder streams per batch request; kept small so a burst stays well under
// the 50-packet recv queue while the client drains in the same loop
static const uint32_t UPDATE_WINDOW_BLOCKS = 16;


class NetworkLink {
public:
    virtual ~NetworkLink() {}
    virtual bool init() = 0;
    virtual void broadcast(const packet_t& packet) = 0;
    virtual bool receive(packet_t& output_packet) = 0;
    virtual void shutdown() = 0;
    virtual void get_status_info(char* out_buf, size_t max_len) = 0;
};
