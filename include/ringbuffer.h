// ringbuffer.h
// fixed-size ring-buffer for staging incoming and outgoing mesh packets

#pragma once

#include "network.h"
#include <cstddef>
#include <cstdint>

uint64_t packet_signature(const packet_t& packet);

class SignatureCache {
public:
    SignatureCache();
    bool seen(uint64_t sig) const;
    void mark_seen(uint64_t sig);
    void clear();
private:
    static const size_t CACHE_CAPACITY = 256;
    uint64_t sigs_[CACHE_CAPACITY];
    size_t head_;
    size_t count_;
};

class PacketRingBuffer {
public:
    PacketRingBuffer();
    ~PacketRingBuffer();

    void push(const packet_t& packet);
    bool pop(packet_t& output_packet);
    bool get_at(size_t index, packet_t& output_packet) const;
    bool contains(const packet_t& packet) const;
    size_t size() const;
    size_t capacity() const;
    void clear();
    // encrypted at rest with the storage keys; load merges (keeps packets
    // received while locked) and verifies the mac before decrypting
    bool save_to_file(const char* filepath, const uint8_t enc_key[32], const uint8_t mac_key[32]) const;
    bool load_from_file(const char* filepath, const uint8_t enc_key[32], const uint8_t mac_key[32]);
    bool delete_store_file(const char* filepath);

private:
    static const size_t BUFFER_CAPACITY = 128;
    packet_t data_[BUFFER_CAPACITY];
    size_t head_;
    size_t tail_;
    size_t size_;
};
