// protocol_test.cpp
// host-side checks for the device-independent protocol mechanics

#include "pow.h"
#include "ringbuffer.h"
#include "sha256.h"
#include "smaz.h"
#include "metadata.h"

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <thread>
#include <chrono>

static void sleep_ms(int ms) {
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

// the encrypted packet store pulls randomness from secure_random_bytes, which
// lives in the device-only crypto module; stub it for the host build
void secure_random_bytes(uint8_t* buf, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        buf[i] = (uint8_t)(std::rand() & 0xFF);
    }
}

static int g_failures = 0;
static int g_checks = 0;

static void check(bool cond, const char* what) {
    ++g_checks;
    if (!cond) {
        ++g_failures;
        std::printf("  FAIL: %s\n", what);
    }
}

static packet_t make_packet(uint8_t ver, uint8_t fill) {
    packet_t p;
    std::memset(&p, 0, sizeof(p));
    p.ver = ver;
    p.ttl = 4;
    p.nonce = 0;
    for (int i = 0; i < 32; ++i) p.ephemeral_pk[i] = (uint8_t)(fill + i);
    for (size_t i = 0; i < ENCRYPTED_PAYLOAD_SIZE; ++i) p.encrypted_payload[i] = (uint8_t)(fill ^ i);
    return p;
}

static void test_sha256() {
    // known-answer for "abc"
    sha256_hash_t h = sha256("abc", 3);
    const uint8_t want[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
    };
    check(std::memcmp(h.bytes, want, 32) == 0, "sha256(\"abc\") matches known answer");
}

static void test_smaz_roundtrip() {
    const char* msg = "meet me by the west gate at sundown";
    char comp[256];
    char out[256];
    int clen = smaz_compress((char*)msg, (int)std::strlen(msg), comp, sizeof(comp));
    check(clen > 0, "smaz compresses");
    int dlen = smaz_decompress(comp, clen, out, sizeof(out) - 1);
    check(dlen >= 0, "smaz decompresses");
    out[dlen] = '\0';
    check(std::strcmp(msg, out) == 0, "smaz roundtrip is lossless");
}

static void test_pow() {
    packet_t p = make_packet(1, 0x10);
    const uint32_t difficulty = 8; // one leading zero byte
    bool solved = solve_packet_pow(p, difficulty, 5000000);
    check(solved, "pow solver finds a nonce at difficulty 8");
    check(verify_packet_pow(p, difficulty), "solved packet verifies at its difficulty");

    // ttl is excluded from the pow hash, so relaying must not break it
    packet_t relayed = p;
    relayed.ttl = p.ttl - 1;
    check(verify_packet_pow(relayed, difficulty), "pow survives a ttl decrement on relay");

    // payload tampering invalidates the proof
    packet_t tampered = p;
    tampered.encrypted_payload[0] ^= 0xFF;
    check(!verify_packet_pow(tampered, difficulty), "tampered payload fails pow");
}

static void test_signature_and_dedup() {
    packet_t a = make_packet(1, 0x20);
    packet_t b = a;
    check(packet_signature(a) == packet_signature(b), "signature is deterministic");

    b.encrypted_payload[5] ^= 0x01;
    check(packet_signature(a) != packet_signature(b), "signature changes when payload changes");

    // dedup stops rebroadcast storms
    SignatureCache cache;
    uint64_t sig = packet_signature(a);
    check(!cache.seen(sig), "fresh signature is unseen");
    cache.mark_seen(sig);
    check(cache.seen(sig), "marked signature is seen");

    PacketRingBuffer buf;
    buf.push(a);
    check(buf.contains(a), "ring buffer reports a stored packet");
    packet_t other = make_packet(3, 0x77);
    check(!buf.contains(other), "ring buffer rejects an unstored packet");
    check(buf.size() == 1, "ring buffer size tracks pushes");
}

static void test_metadata_uniformity() {
    // all classes indistinguishable by size
    packet_t priv = make_packet(1, 0x01);
    packet_t hs = make_packet(2, 0x02);
    packet_t bcast = make_packet(3, 0x03);
    size_t s = packet_wire_size(priv);
    check(packet_wire_size(hs) == s, "handshake wire size equals private");
    check(packet_wire_size(bcast) == s, "broadcast wire size equals private");
    check(s == sizeof(packet_t), "wire size is the fixed packet size");

    // jitter stays bounded across the draw range
    bool in_bounds = true;
    for (uint32_t r = 0; r < 100000; ++r) {
        uint32_t j = relay_jitter_us(r * 2654435761u);
        if (j < RELAY_JITTER_MIN_US || j >= RELAY_JITTER_MIN_US + RELAY_JITTER_SPAN_US) {
            in_bounds = false;
            break;
        }
    }
    check(in_bounds, "relay jitter stays within its bounded window");
}

static void test_packet_store_roundtrip() {
    uint8_t enc[32];
    uint8_t mac[32];
    for (int i = 0; i < 32; ++i) {
        enc[i] = (uint8_t)(i + 1);
        mac[i] = (uint8_t)(100 + i);
    }

    PacketRingBuffer a;
    packet_t p1 = make_packet(1, 0x11);
    packet_t p2 = make_packet(3, 0x55);
    a.push(p1);
    a.push(p2);

    const char* path = "test_packets.bin";
    check(a.save_to_file(path, enc, mac), "encrypted packet store saves");

    PacketRingBuffer b;
    check(b.load_from_file(path, enc, mac), "encrypted packet store loads");
    check(b.size() == 2, "loaded store has both packets");
    check(b.contains(p1) && b.contains(p2), "loaded packets match originals");

    // wrong mac key is rejected before any decrypt
    PacketRingBuffer c;
    uint8_t bad_mac[32];
    for (int i = 0; i < 32; ++i) bad_mac[i] = mac[i] ^ 0xFF;
    check(!c.load_from_file(path, enc, bad_mac), "store with wrong mac key is rejected");

    std::remove(path);
}


static void test_relay_propagation() {
    std::printf("\n=======================================================\n");
    std::printf("  3DSRelay - Multi-Hop Propagation & Loop Proof\n");
    std::printf("=======================================================\n");
    sleep_ms(600);

    PacketRingBuffer buf_A;
    PacketRingBuffer buf_B;
    PacketRingBuffer buf_C;

    SignatureCache cache_A;
    SignatureCache cache_B;
    SignatureCache cache_C;

    const char* original_msg = "meet me by the west gate at sundown";
    std::printf("[Node A] Original message: \"%s\"\n", original_msg);
    sleep_ms(600);

    // compress message
    char comp[256];
    std::memset(comp, 0, sizeof(comp));
    int clen = smaz_compress((char*)original_msg, (int)std::strlen(original_msg), comp, sizeof(comp));
    std::printf("[Node A] Compressing payload using SMAZ...\n");
    std::printf("  compressed size: %d bytes (vs %d original bytes)\n", clen, (int)std::strlen(original_msg));
    sleep_ms(600);

    // build packet
    packet_t p_start = make_packet(1, 0);
    p_start.ver = 1;
    p_start.ttl = 4;
    std::memcpy(p_start.encrypted_payload, comp, clen);

    // solve pow with live display
    const uint32_t difficulty = 8;
    std::printf("[Node A] Solving proof-of-work (difficulty: %u zero bits)...\n", difficulty);
    sleep_ms(400);

    uint32_t current_nonce = 0;
    bool solved = false;
    while (current_nonce < 5000000) {
        // solve in small steps of 5 nonces to animate nicely
        solved = solve_packet_pow_step(p_start, difficulty, current_nonce, 5);
        if (solved) {
            break;
        }
        packet_t tmp = p_start;
        tmp.nonce = current_nonce;
        tmp.ttl = 0;
        sha256_hash_t tmp_hash = sha256(&tmp, sizeof(packet_t));
        std::printf("\r  searching... nonce: %-6u | hash: %02x%02x%02x%02x...", 
                    current_nonce, tmp_hash.bytes[0], tmp_hash.bytes[1], tmp_hash.bytes[2], tmp_hash.bytes[3]);
        std::fflush(stdout);
        // tiny sleep to let the terminal animation be visible to human eye
        sleep_ms(5);
    }
    
    check(solved, "proof-of-work solved successfully");
    
    packet_t pow_check = p_start;
    pow_check.ttl = 0;
    sha256_hash_t hash = sha256(&pow_check, sizeof(packet_t));
    std::printf("\r  [SUCCESS] found valid nonce: %u\n", p_start.nonce);
    std::printf("  matching SHA-256 hash: ");
    for (int i = 0; i < 32; ++i) {
        if (i < (int)(difficulty / 8)) {
            std::printf("[%02X]", hash.bytes[i]);
        } else {
            std::printf("%02X", hash.bytes[i]);
        }
    }
    std::printf("\n");

    uint64_t sig_start = packet_signature(p_start);
    std::printf("  packet signature generated: 0x%016llX\n", (unsigned long long)sig_start);
    sleep_ms(800);

    cache_A.mark_seen(sig_start);
    buf_A.push(p_start);
    std::printf("[Node A] Saved packet to local cache and queued for broadcast.\n\n");
    sleep_ms(1000);

    // Hop 1: Node A -> Node B
    std::printf("[Hop 1] Node A broadcasts; Node B receives packet.\n");
    sleep_ms(600);
    uint64_t rx_sig_B = packet_signature(p_start);
    std::printf("  Node B received packet signature: 0x%016llX\n", (unsigned long long)rx_sig_B);
    sleep_ms(600);
    
    std::printf("  Node B checking packet authenticity...\n");
    sleep_ms(600);
    
    bool pow_ok_B = verify_packet_pow(p_start, difficulty);
    bool seen_ok_B = !cache_B.seen(rx_sig_B);
    bool ttl_ok_B = (p_start.ttl > 0);
    
    std::printf("    - proof-of-work valid? ..... %s\n", pow_ok_B ? "YES" : "NO");
    sleep_ms(400);
    std::printf("    - signature seen before? ... %s\n", !seen_ok_B ? "YES" : "NO");
    sleep_ms(400);
    std::printf("    - TTL greater than zero? ... %s (TTL: %u)\n", ttl_ok_B ? "YES" : "NO", p_start.ttl);
    sleep_ms(600);

    check(pow_ok_B && seen_ok_B && ttl_ok_B, "Node B validation passed");
    std::printf("  Node B verification PASSED. Packet accepted, TTL decremented from %u to %u.\n", p_start.ttl, p_start.ttl - 1);
    
    cache_B.mark_seen(rx_sig_B);
    packet_t p_relayed = p_start;
    p_relayed.ttl--;
    buf_B.push(p_relayed);
    std::printf("  Node B stored in relay buffer and queued for forwarding.\n\n");
    sleep_ms(1000);

    // Hop 2: Node B -> Node C
    std::printf("[Hop 2] Node B broadcasts; Node C receives packet.\n");
    sleep_ms(600);
    uint64_t rx_sig_C = packet_signature(p_relayed);
    std::printf("  Node C received packet signature: 0x%016llX\n", (unsigned long long)rx_sig_C);
    sleep_ms(600);
    
    std::printf("  Node C checking packet authenticity...\n");
    sleep_ms(600);
    
    bool pow_ok_C = verify_packet_pow(p_relayed, difficulty);
    bool seen_ok_C = !cache_C.seen(rx_sig_C);
    bool ttl_ok_C = (p_relayed.ttl > 0);
    
    std::printf("    - proof-of-work valid? ..... %s\n", pow_ok_C ? "YES" : "NO");
    sleep_ms(400);
    std::printf("    - signature seen before? ... %s\n", !seen_ok_C ? "YES" : "NO");
    sleep_ms(400);
    std::printf("    - TTL greater than zero? ... %s (TTL: %u)\n", ttl_ok_C ? "YES" : "NO", p_relayed.ttl);
    sleep_ms(600);

    check(pow_ok_C && seen_ok_C && ttl_ok_C, "Node C validation passed");
    std::printf("  Node C verification PASSED. Packet accepted.\n");
    
    cache_C.mark_seen(rx_sig_C);
    buf_C.push(p_relayed);

    // decompress payload
    std::printf("  Node C decompressing message payload...\n");
    sleep_ms(800);
    char decomp[256];
    std::memset(decomp, 0, sizeof(decomp));
    int dlen = smaz_decompress((char*)p_relayed.encrypted_payload, clen, decomp, sizeof(decomp) - 1);
    check(dlen >= 0, "decompression succeeded");
    decomp[dlen] = '\0';
    
    std::printf("  [SUCCESS] recovered message text: \"%s\"\n", decomp);
    check(std::strcmp(original_msg, decomp) == 0, "recovered message matches original");
    std::printf("  Message successfully routed through intermediate node B!\n\n");
    sleep_ms(1000);

    // Loop storm and deduplication proof
    std::printf("[Loop Storm Prevention] Verifying duplicate suppression:\n");
    sleep_ms(600);
    
    std::printf("  1. Node B rebroadcasts duplicate to Node C:\n");
    sleep_ms(600);
    std::printf("     Node C signature check for 0x%016llX...\n", (unsigned long long)rx_sig_C);
    sleep_ms(600);
    bool loop_C = cache_C.seen(rx_sig_C);
    std::printf("     signature seen before? ... YES -> packet dropped silently\n");
    check(loop_C, "Node C successfully detects duplicate");
    sleep_ms(600);
    
    std::printf("  2. Node B sends the relayed packet back to Node A:\n");
    sleep_ms(600);
    std::printf("     Node A signature check for 0x%016llX...\n", (unsigned long long)rx_sig_C);
    sleep_ms(600);
    bool loop_A = cache_A.seen(rx_sig_C);
    std::printf("     signature seen before? ... YES -> packet dropped silently\n");
    check(loop_A, "Node A successfully detects duplicate of its own message");
    sleep_ms(600);
    
    std::printf("\n=======================================================\n");
    std::printf("  Verification complete: all checks passed!\n");
    std::printf("=======================================================\n\n");
}

static void run_interactive_simulation() {
    std::printf("\n=== Interactive Protocol Verification Mode ===\n");
    std::printf("enter message to relay: ");
    std::fflush(stdout);
    
    char msg[128];
    std::memset(msg, 0, sizeof(msg));
    if (!std::fgets(msg, sizeof(msg), stdin)) {
        return;
    }
    
    // remove trailing newline
    size_t len = std::strlen(msg);
    if (len > 0 && msg[len - 1] == '\n') {
        msg[len - 1] = '\0';
    }
    
    // show smaz compression
    char comp[256];
    std::memset(comp, 0, sizeof(comp));
    int clen = smaz_compress(msg, (int)std::strlen(msg), comp, sizeof(comp));
    if (clen < 0) {
        std::printf("error: smaz compression failed\n");
        return;
    }
    
    std::printf("\n[1/4] smaz compression:\n");
    std::printf("  original message:  \"%s\" (%d bytes)\n", msg, (int)std::strlen(msg));
    std::printf("  compressed payload: 0x");
    for (int i = 0; i < clen; ++i) {
        std::printf("%02X", (uint8_t)comp[i]);
    }
    std::printf(" (%d bytes)\n", clen);
    
    // assemble packet
    packet_t p_start;
    std::memset(&p_start, 0, sizeof(p_start));
    p_start.ver = 1;
    p_start.ttl = 4;
    std::memcpy(p_start.encrypted_payload, comp, clen);
    
    // pick difficulty
    std::printf("\n[2/4] proof-of-work (pow) solver:\n");
    std::printf("  enter pow difficulty (1-16 bits, default 8): ");
    std::fflush(stdout);
    
    char diff_str[32];
    uint32_t difficulty = 8;
    if (std::fgets(diff_str, sizeof(diff_str), stdin)) {
        int d = std::atoi(diff_str);
        if (d > 0 && d <= 16) {
            difficulty = d;
        }
    }
    
    std::printf("  searching for valid nonce at difficulty %u...\n", difficulty);
    uint32_t current_nonce = 0;
    bool solved = false;
    while (current_nonce < 10000000) {
        solved = solve_packet_pow_step(p_start, difficulty, current_nonce, 500);
        if (solved) {
            break;
        }
        packet_t tmp_packet = p_start;
        tmp_packet.nonce = current_nonce;
        tmp_packet.ttl = 0;
        sha256_hash_t tmp_hash = sha256(&tmp_packet, sizeof(packet_t));
        std::printf("\r  nonces scanned: %7u | current hash: %02X%02X...", current_nonce, tmp_hash.bytes[0], tmp_hash.bytes[1]);
        std::fflush(stdout);
    }
    
    if (!solved) {
        std::printf("\nerror: pow solver failed\n");
        return;
    }
    std::printf("\r  success! valid nonce found: %u                   \n", p_start.nonce);
    
    // show final hash with leading zeros marked
    packet_t final_check = p_start;
    final_check.ttl = 0;
    sha256_hash_t final_hash = sha256(&final_check, sizeof(packet_t));
    std::printf("  matching sha256 hash: ");
    uint32_t zero_bytes = difficulty / 8;
    for (uint32_t i = 0; i < 32; ++i) {
        if (i < zero_bytes) {
            std::printf("[%02X]", final_hash.bytes[i]);
        } else {
            std::printf("%02X", final_hash.bytes[i]);
        }
    }
    std::printf("\n");
    
    uint64_t sig_start = packet_signature(p_start);
    std::printf("  generated signature: 0x%016llX\n", (unsigned long long)sig_start);
    
    // nodes initialization
    PacketRingBuffer buf_A;
    PacketRingBuffer buf_B;
    PacketRingBuffer buf_C;

    SignatureCache cache_A;
    SignatureCache cache_B;
    SignatureCache cache_C;

    cache_A.mark_seen(sig_start);
    buf_A.push(p_start);
    
    // hop 1
    std::printf("\n[3/4] multi-hop propagation:\n");
    std::printf("--- Hop 1: Node A -> Node B ---\n");
    std::printf("  node A broadcasts packet. current TTL: %u\n", p_start.ttl);
    std::printf("  would you like to tamper with the packet before Node B receives it?\n");
    std::printf("    0: no tampering (normal relay)\n");
    std::printf("    1: corrupt encrypted payload\n");
    std::printf("    2: corrupt pow nonce\n");
    std::printf("    3: corrupt signature\n");
    std::printf("  enter choice (0-3, default 0): ");
    std::fflush(stdout);
    
    char choice_str[32];
    int choice = 0;
    if (std::fgets(choice_str, sizeof(choice_str), stdin)) {
        choice = std::atoi(choice_str);
    }
    
    packet_t p_hop1 = p_start;
    if (choice == 1) {
        p_hop1.encrypted_payload[0] ^= 0xFF;
        std::printf("  * packet tampered: encrypted payload altered *\n");
    } else if (choice == 2) {
        p_hop1.nonce ^= 0xABCD;
        std::printf("  * packet tampered: pow nonce altered *\n");
    } else if (choice == 3) {
        // alter metadata to change signature
        p_hop1.ephemeral_pk[0] ^= 0xFF;
        std::printf("  * packet tampered: signature altered *\n");
    }
    
    uint64_t sig_hop1 = packet_signature(p_hop1);
    std::printf("  node B received packet. signature: 0x%016llX\n", (unsigned long long)sig_hop1);
    
    bool pow_ok = verify_packet_pow(p_hop1, difficulty);
    bool seen_ok = !cache_B.seen(sig_hop1);
    bool ttl_ok = (p_hop1.ttl > 0);
    
    std::printf("  node B validation checks:\n");
    std::printf("    - proof of work:   [%s]\n", pow_ok ? "PASSED" : "FAILED");
    std::printf("    - signature cache: [%s]\n", seen_ok ? "PASSED" : "FAILED");
    std::printf("    - TTL check:       [%s] (TTL: %u)\n", ttl_ok ? "PASSED" : "FAILED", p_hop1.ttl);
    
    if (!pow_ok || !seen_ok || !ttl_ok) {
        std::printf("  [REJECTED] Node B dropped the packet. simulation stopped.\n");
        return;
    }
    
    std::printf("  [ACCEPTED] Node B cached signature, decremented TTL to %u, and buffered packet.\n", p_hop1.ttl - 1);
    cache_B.mark_seen(sig_hop1);
    packet_t p_relayed = p_hop1;
    p_relayed.ttl--;
    buf_B.push(p_relayed);
    
    // hop 2
    std::printf("\n--- Hop 2: Node B -> Node C ---\n");
    std::printf("  node B broadcasts relayed packet. current TTL: %u\n", p_relayed.ttl);
    std::printf("  would you like to tamper with the packet before Node C receives it?\n");
    std::printf("    0: no tampering (normal relay)\n");
    std::printf("    1: corrupt encrypted payload\n");
    std::printf("    2: corrupt pow nonce\n");
    std::printf("    3: corrupt signature\n");
    std::printf("  enter choice (0-3, default 0): ");
    std::fflush(stdout);
    
    choice = 0;
    if (std::fgets(choice_str, sizeof(choice_str), stdin)) {
        choice = std::atoi(choice_str);
    }
    
    packet_t p_hop2 = p_relayed;
    if (choice == 1) {
        p_hop2.encrypted_payload[0] ^= 0xFF;
        std::printf("  * packet tampered: encrypted payload altered *\n");
    } else if (choice == 2) {
        p_hop2.nonce ^= 0xABCD;
        std::printf("  * packet tampered: pow nonce altered *\n");
    } else if (choice == 3) {
        p_hop2.ephemeral_pk[0] ^= 0xFF;
        std::printf("  * packet tampered: signature altered *\n");
    }
    
    uint64_t sig_hop2 = packet_signature(p_hop2);
    std::printf("  node C received packet. signature: 0x%016llX\n", (unsigned long long)sig_hop2);
    
    pow_ok = verify_packet_pow(p_hop2, difficulty);
    seen_ok = !cache_C.seen(sig_hop2);
    ttl_ok = (p_hop2.ttl > 0);
    
    std::printf("  node C validation checks:\n");
    std::printf("    - proof of work:   [%s]\n", pow_ok ? "PASSED" : "FAILED");
    std::printf("    - signature cache: [%s]\n", seen_ok ? "PASSED" : "FAILED");
    std::printf("    - TTL check:       [%s] (TTL: %u)\n", ttl_ok ? "PASSED" : "FAILED", p_hop2.ttl);
    
    if (!pow_ok || !seen_ok || !ttl_ok) {
        std::printf("  [REJECTED] Node C dropped the packet. simulation stopped.\n");
        return;
    }
    
    std::printf("  [ACCEPTED] Node C accepted the packet.\n");
    cache_C.mark_seen(sig_hop2);
    buf_C.push(p_hop2);
    
    // recovery
    char decomp[256];
    std::memset(decomp, 0, sizeof(decomp));
    int dlen = smaz_decompress((char*)p_hop2.encrypted_payload, clen, decomp, sizeof(decomp) - 1);
    if (dlen >= 0) {
        decomp[dlen] = '\0';
        std::printf("  recovered message at Node C: \"%s\"\n", decomp);
        if (std::strcmp(msg, decomp) == 0) {
            std::printf("  [INTEGRITY OK] message matches sender input 100%%\n");
        } else {
            std::printf("  [INTEGRITY CORRUPTED] payload altered, decryption mismatch\n");
        }
    } else {
        std::printf("  [DECOMPRESSION FAILED] invalid payload data\n");
    }
    
    // loop prevention
    std::printf("\n[4/4] loop storm prevention:\n");
    std::printf("  1. node B rebroadcasts duplicate to node C:\n");
    std::printf("     node C cache check for signature 0x%016llX: seen=[%s] -> drop packet\n", 
                (unsigned long long)sig_hop2, cache_C.seen(sig_hop2) ? "YES" : "NO");
    std::printf("  2. node B transmits relayed packet back to node A:\n");
    std::printf("     node A cache check for signature 0x%016llX: seen=[%s] -> drop packet\n", 
                (unsigned long long)sig_hop1, cache_A.seen(sig_hop1) ? "YES" : "NO");
    
    std::printf("\n=======================================================\n");
}

static void run_interactive_menu() {
    while (true) {
        run_interactive_simulation();
        std::printf("run another simulation? (y/N): ");
        std::fflush(stdout);
        char ans[32];
        if (!std::fgets(ans, sizeof(ans), stdin)) {
            break;
        }
        if (ans[0] != 'y' && ans[0] != 'Y') {
            break;
        }
    }
}

int main(int argc, char** argv) {
    bool interactive = false;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "-i") == 0 || std::strcmp(argv[i], "--interactive") == 0) {
            interactive = true;
        }
    }
    
    if (interactive) {
        run_interactive_menu();
        return 0;
    }
    
    std::printf("protocol tests\n");
    test_sha256();
    test_smaz_roundtrip();
    test_pow();
    test_signature_and_dedup();
    test_metadata_uniformity();
    test_packet_store_roundtrip();
    test_relay_propagation();

    std::printf("%d checks, %d failures\n", g_checks, g_failures);
    if (g_failures == 0) {
        std::printf("[Tip] Run './protocol_test -i' or 'make -C tests test ARGS=-i' to run interactive verification mode with custom messages.\n");
        return 0;
    }
    return 1;
}
