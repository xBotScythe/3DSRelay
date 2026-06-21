// ringbuffer.cpp
// ring-buffer and signature cache operations

#include "ringbuffer.h"
#include "chacha20.h" // chacha20_crypt + secure_random_bytes
#include "sha256.h"   // hmac_sha256
#include <cstring>
#include <cstdio>
#include <cstdlib>

uint64_t packet_signature(const packet_t& packet) {
    uint64_t h = 0xcbf29ce484222325ULL;
    const uint64_t prime = 0x100000001b3ULL;
    h ^= (uint64_t)packet.ver; h *= prime;
    h ^= (uint64_t)packet.nonce; h *= prime;
    for (int i = 0; i < 32; ++i) {
        h ^= packet.ephemeral_pk[i]; h *= prime;
    }
    for (size_t i = 0; i < ENCRYPTED_PAYLOAD_SIZE; ++i) {
        h ^= packet.encrypted_payload[i]; h *= prime;
    }
    return h;
}

SignatureCache::SignatureCache() : head_(0), count_(0) {
    std::memset(sigs_, 0, sizeof(sigs_));
}

bool SignatureCache::seen(uint64_t sig) const {
    for (size_t i = 0; i < count_; ++i) {
        if (sigs_[i] == sig) return true;
    }
    return false;
}

void SignatureCache::mark_seen(uint64_t sig) {
    sigs_[head_] = sig;
    head_ = (head_ + 1) % CACHE_CAPACITY;
    if (count_ < CACHE_CAPACITY) count_++;
}

void SignatureCache::clear() {
    head_ = 0;
    count_ = 0;
    std::memset(sigs_, 0, sizeof(sigs_));
}

PacketRingBuffer::PacketRingBuffer() : head_(0), tail_(0), size_(0) {
    std::memset(data_, 0, sizeof(data_));
}

PacketRingBuffer::~PacketRingBuffer() {}

void PacketRingBuffer::push(const packet_t& packet) {
    if (size_ == BUFFER_CAPACITY) {
        // buffer full, advance tail to evict oldest item
        tail_ = (tail_ + 1) % BUFFER_CAPACITY;
        size_--;
    }
    data_[head_] = packet;
    head_ = (head_ + 1) % BUFFER_CAPACITY;
    size_++;
}

bool PacketRingBuffer::pop(packet_t& output_packet) {
    if (size_ == 0) {
        return false;
    }
    output_packet = data_[tail_];
    tail_ = (tail_ + 1) % BUFFER_CAPACITY;
    size_--;
    return true;
}

bool PacketRingBuffer::get_at(size_t index, packet_t& output_packet) const {
    if (index >= size_) {
        return false;
    }
    size_t target_index = (tail_ + index) % BUFFER_CAPACITY;
    output_packet = data_[target_index];
    return true;
}

bool PacketRingBuffer::contains(const packet_t& packet) const {
    for (size_t i = 0; i < size_; ++i) {
        size_t index = (tail_ + i) % BUFFER_CAPACITY;
        const packet_t& p = data_[index];

        // compare immutable identity fields only (TTL changes during routing)
        if (p.ver == packet.ver &&
            p.nonce == packet.nonce &&
            std::memcmp(p.ephemeral_pk, packet.ephemeral_pk, sizeof(p.ephemeral_pk)) == 0 &&
            std::memcmp(p.encrypted_payload, packet.encrypted_payload, sizeof(p.encrypted_payload)) == 0) {
            return true;
        }
    }
    return false;
}

size_t PacketRingBuffer::size() const {
    return size_;
}

size_t PacketRingBuffer::capacity() const {
    return BUFFER_CAPACITY;
}

void PacketRingBuffer::clear() {
    head_ = 0;
    tail_ = 0;
    size_ = 0;
    std::memset(data_, 0, sizeof(data_));
}

bool PacketRingBuffer::save_to_file(const char* filepath, const uint8_t enc_key[32], const uint8_t mac_key[32]) const {
    char tmp_path[256];
    std::snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", filepath);
    std::FILE* f = std::fopen(tmp_path, "wb");
    if (!f) {
        return false;
    }

    size_t count = size_;
    size_t body = sizeof(size_t) + count * sizeof(packet_t);
    uint8_t* plain = (uint8_t*)std::malloc(body);
    uint8_t* cipher = (uint8_t*)std::malloc(body);
    uint8_t* mac_input = (uint8_t*)std::malloc(12 + body);
    if (!plain || !cipher || !mac_input) {
        std::free(plain); std::free(cipher); std::free(mac_input);
        std::fclose(f);
        return false;
    }

    std::memcpy(plain, &count, sizeof(size_t));
    for (size_t i = 0; i < count; ++i) {
        packet_t p;
        get_at(i, p);
        std::memcpy(plain + sizeof(size_t) + i * sizeof(packet_t), &p, sizeof(packet_t));
    }

    uint8_t nonce[12];
    secure_random_bytes(nonce, 12);
    chacha20_crypt(enc_key, nonce, 0, plain, cipher, body);

    // encrypt-then-mac over nonce||ciphertext
    std::memcpy(mac_input, nonce, 12);
    std::memcpy(mac_input + 12, cipher, body);
    sha256_hash_t mac = hmac_sha256(mac_key, 32, mac_input, 12 + body);

    std::fwrite(nonce, 12, 1, f);
    std::fwrite(mac.bytes, 32, 1, f);
    std::fwrite(cipher, 1, body, f);
    std::fflush(f);
    std::fclose(f);
    std::remove(filepath);
    std::rename(tmp_path, filepath);

    std::memset(plain, 0, body);
    std::free(plain); std::free(cipher); std::free(mac_input);
    return true;
}

bool PacketRingBuffer::load_from_file(const char* filepath, const uint8_t enc_key[32], const uint8_t mac_key[32]) {
    std::FILE* f = std::fopen(filepath, "rb");
    if (!f) {
        return false;
    }
    std::fseek(f, 0, SEEK_END);
    long fsz = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    if (fsz < (long)(12 + 32 + sizeof(size_t))) {
        std::fclose(f);
        return false;
    }

    size_t body = (size_t)fsz - 12 - 32;
    uint8_t nonce[12];
    uint8_t mac_read[32];
    uint8_t* cipher = (uint8_t*)std::malloc(body);
    uint8_t* mac_input = (uint8_t*)std::malloc(12 + body);
    if (!cipher || !mac_input) {
        std::free(cipher); std::free(mac_input);
        std::fclose(f);
        return false;
    }
    if (std::fread(nonce, 12, 1, f) != 1 ||
        std::fread(mac_read, 32, 1, f) != 1 ||
        std::fread(cipher, 1, body, f) != body) {
        std::free(cipher); std::free(mac_input);
        std::fclose(f);
        return false;
    }
    std::fclose(f);

    // verify before decrypting
    std::memcpy(mac_input, nonce, 12);
    std::memcpy(mac_input + 12, cipher, body);
    sha256_hash_t mac = hmac_sha256(mac_key, 32, mac_input, 12 + body);
    uint8_t diff = 0;
    for (int i = 0; i < 32; ++i) {
        diff |= mac.bytes[i] ^ mac_read[i];
    }
    std::free(mac_input);
    if (diff != 0) {
        std::free(cipher);
        return false;
    }

    uint8_t* plain = (uint8_t*)std::malloc(body);
    if (!plain) {
        std::free(cipher);
        return false;
    }
    chacha20_crypt(enc_key, nonce, 0, cipher, plain, body);
    std::free(cipher);

    size_t count = 0;
    std::memcpy(&count, plain, sizeof(size_t));
    size_t max_count = (body - sizeof(size_t)) / sizeof(packet_t);
    if (count > max_count) {
        count = max_count;
    }
    for (size_t i = 0; i < count; ++i) {
        packet_t p;
        std::memcpy(&p, plain + sizeof(size_t) + i * sizeof(packet_t), sizeof(packet_t));
        // merge: don't drop packets already buffered while locked
        if (!contains(p)) {
            push(p);
        }
    }
    std::memset(plain, 0, body);
    std::free(plain);
    return true;
}

bool PacketRingBuffer::delete_store_file(const char* filepath) {
    // multi-pass overwrite to raise forensic recovery cost
    std::FILE* f = std::fopen(filepath, "r+b");
    if (f) {
        std::fseek(f, 0, SEEK_END);
        long sz = std::ftell(f);
        if (sz > 0) {
            char* wipe_buf = (char*)std::calloc(sz, 1);
            if (wipe_buf) {
                // pass 1: zero fill
                std::fseek(f, 0, SEEK_SET);
                std::fwrite(wipe_buf, 1, sz, f);
                std::fflush(f);

                // pass 2: 0xFF fill
                std::memset(wipe_buf, 0xFF, sz);
                std::fseek(f, 0, SEEK_SET);
                std::fwrite(wipe_buf, 1, sz, f);
                std::fflush(f);

                // pass 3: pseudo-random fill
                for (long i = 0; i < sz; ++i) {
                    wipe_buf[i] = (char)(std::rand() & 0xFF);
                }
                std::fseek(f, 0, SEEK_SET);
                std::fwrite(wipe_buf, 1, sz, f);
                std::fflush(f);

                // pass 4: final zero fill
                std::memset(wipe_buf, 0, sz);
                std::fseek(f, 0, SEEK_SET);
                std::fwrite(wipe_buf, 1, sz, f);
                std::fflush(f);

                std::free(wipe_buf);
            }
        }
        std::fclose(f);
    }
    std::remove(filepath);
    return true;
}
