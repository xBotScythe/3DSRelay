// metadata.h
// traffic-uniformity helpers for the relay path

#pragma once

#include "network.h"
#include <cstdint>
#include <cstddef>

// pre-send jitter window in microseconds
static const uint32_t RELAY_JITTER_MIN_US = 1000;
static const uint32_t RELAY_JITTER_SPAN_US = 4000;

// fixed wire size across all packet classes
size_t packet_wire_size(const packet_t& packet);

// maps a random draw onto the bounded jitter window
uint32_t relay_jitter_us(uint32_t rnd);
