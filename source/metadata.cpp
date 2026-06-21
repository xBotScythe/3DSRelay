// metadata.cpp
// traffic-uniformity helpers

#include "metadata.h"

size_t packet_wire_size(const packet_t& packet) {
    (void)packet;
    return sizeof(packet_t);
}

uint32_t relay_jitter_us(uint32_t rnd) {
    return RELAY_JITTER_MIN_US + (rnd % RELAY_JITTER_SPAN_US);
}
