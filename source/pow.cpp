// pow.cpp
// proof-of-work validation and solver implementation

#include "pow.h"

bool verify_packet_pow(const packet_t& packet, uint32_t difficulty) {
    packet_t pow_packet = packet;
    pow_packet.ttl = 0;
    sha256_hash_t hash = sha256(&pow_packet, sizeof(packet_t));
    
    // check leading zero bytes for quick rejection of invalid hashes
    uint32_t zero_bytes = difficulty / 8;
    for (uint32_t i = 0; i < zero_bytes; ++i) {
        if (hash.bytes[i] != 0) {
            return false;
        }
    }
    
    uint32_t remaining_bits = difficulty % 8;
    if (remaining_bits > 0) {
        uint8_t byte_val = hash.bytes[zero_bytes];
        if ((byte_val >> (8 - remaining_bits)) != 0) {
            return false;
        }
    }
    
    return true;
}

bool solve_packet_pow_step(packet_t& packet, uint32_t difficulty, uint32_t& current_nonce, uint32_t steps) {
    packet_t pow_packet = packet;
    pow_packet.ttl = 0;
    
    uint32_t zero_bytes = difficulty / 8;
    uint32_t remaining_bits = difficulty % 8;
    uint32_t shift_val = 8 - remaining_bits;
    
    for (uint32_t i = 0; i < steps; ++i) {
        pow_packet.nonce = current_nonce;
        sha256_hash_t hash = sha256(&pow_packet, sizeof(packet_t));
        
        bool ok = true;
        for (uint32_t j = 0; j < zero_bytes; ++j) {
            if (hash.bytes[j] != 0) {
                ok = false;
                break;
            }
        }
        if (ok && remaining_bits > 0) {
            if ((hash.bytes[zero_bytes] >> shift_val) != 0) {
                ok = false;
            }
        }
        
        if (ok) {
            packet.nonce = current_nonce;
            return true;
        }
        current_nonce++;
    }
    return false;
}

bool solve_packet_pow(packet_t& packet, uint32_t difficulty, uint32_t max_iterations) {
    uint32_t current_nonce = 0;
    return solve_packet_pow_step(packet, difficulty, current_nonce, max_iterations);
}
