// pow.h
// proof-of-work nonce system for rate limiting and packet validation

#pragma once

#include "network.h"
#include "sha256.h"

// verifies if the packet satisfies the required proof-of-work difficulty
bool verify_packet_pow(const packet_t& packet, uint32_t difficulty);

// solves the proof-of-work for a packet by finding a valid nonce
// returns false if max iterations exceeded
bool solve_packet_pow(packet_t& packet, uint32_t difficulty, uint32_t max_iterations = 10000000);

// incrementally solves proof-of-work in steps to keep user interface responsive
bool solve_packet_pow_step(packet_t& packet, uint32_t difficulty, uint32_t& current_nonce, uint32_t steps);
