// ringbuffer.cpp
// ring-buffer and signature cache operations

#include "ringbuffer.h"
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

bool PacketRingBuffer::save_to_file(const char* filepath) const {
    char tmp_path[256];
    std::snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", filepath);
    std::FILE* f = std::fopen(tmp_path, "wb");
    if (!f) {
        return false;
    }
    size_t count = size_;
    std::fwrite(&count, sizeof(count), 1, f);
    for (size_t i = 0; i < count; ++i) {
        packet_t p;
        if (get_at(i, p)) {
            std::fwrite(&p, sizeof(packet_t), 1, f);
        }
    }
    std::fflush(f);
    std::fclose(f);
    std::rename(tmp_path, filepath);
    return true;
}

bool PacketRingBuffer::load_from_file(const char* filepath) {
    std::FILE* f = std::fopen(filepath, "rb");
    if (!f) {
        return false;
    }
    clear();
    size_t count = 0;
    if (std::fread(&count, sizeof(count), 1, f) != 1) {
        std::fclose(f);
        return false;
    }
    for (size_t i = 0; i < count; ++i) {
        packet_t p;
        if (std::fread(&p, sizeof(packet_t), 1, f) == 1) {
            push(p);
        }
    }
    std::fclose(f);
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
