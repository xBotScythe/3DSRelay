// update_manager.cpp
#include "update_manager.h"
#include "network_impl.h"
#include "crypto_utils.h"
#include "sha256.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>

#include <3ds.h>
#include "ui_rendering.h"


void draw_update_notice(C2D_TextBuf text_buf, C3D_RenderTarget* bottom_target, const char* title, const char* body) {
    C2D_TextBufClear(text_buf);
    C3D_FrameBegin(C3D_FRAME_SYNCDRAW);
    C2D_TargetClear(bottom_target, C2D_Color32(11, 12, 16, 255));
    C2D_SceneBegin(bottom_target);

    C2D_DrawRectSolid(0, 0, 0.5f, 320, 28, C2D_Color32(26, 27, 38, 255));
    draw_text(text_buf, title, 12, 6, 0.55f, C2D_Color32(0, 255, 210, 255));
    C2D_DrawRectSolid(0, 28, 0.5f, 320, 1, C2D_Color32(0, 255, 210, 80));
    draw_text(text_buf, body, 12, 48, 0.42f, C2D_Color32(255, 255, 255, 255));

    C3D_FrameEnd(0);
    gspWaitForVBlank();
}

bool install_cia(const char* cia_path, C2D_TextBuf text_buf, C3D_RenderTarget* bottom_target) {
    draw_update_notice(text_buf, bottom_target, "Check for Updates", "Installing update, please wait...");
    
    FILE* install_f = std::fopen(cia_path, "rb");
    if (!install_f) {
        draw_update_notice(text_buf, bottom_target, "Check for Updates", "Error: failed to open install file.");
        svcSleepThread(3000000000ULL);
        return false;
    }
    
    // execute AM title installation on SD card
    Handle ciaInstallHandle = 0;
    Result res = AM_StartCiaInstall(MEDIATYPE_SD, &ciaInstallHandle);
    if (R_FAILED(res)) {
        std::fclose(install_f);
        std::remove(cia_path);
        char err_msg[128];
        std::snprintf(err_msg, sizeof(err_msg), "Error: AM_StartCiaInstall failed (0x%08lX)", (unsigned long)res);
        draw_update_notice(text_buf, bottom_target, "Check for Updates", err_msg);
        svcSleepThread(3000000000ULL);
        return false;
    }
    
    uint8_t write_buf[16384];
    bool install_success = true;
    u64 install_offset = 0;
    size_t rb = 0;
    while ((rb = std::fread(write_buf, 1, sizeof(write_buf), install_f)) > 0) {
        u32 written = 0;
        // write update partition data sequentially with tracking offset
        res = FSFILE_Write(ciaInstallHandle, &written, install_offset, write_buf, rb, 0);
        if (R_FAILED(res) || written != rb) {
            install_success = false;
            break;
        }
        install_offset += written;
    }
    std::fclose(install_f);
    std::remove(cia_path);
    
    if (install_success) {
        res = AM_FinishCiaInstall(ciaInstallHandle);
        if (R_SUCCEEDED(res)) {
            draw_update_notice(text_buf, bottom_target, "Check for Updates", "Update installed. Closing...");
            svcSleepThread(2000000000ULL);
            exit(0);
            return true;
        } else {
            char err_msg[128];
            std::snprintf(err_msg, sizeof(err_msg), "Error: AM_FinishCiaInstall failed (0x%08lX)", (unsigned long)res);
            draw_update_notice(text_buf, bottom_target, "Check for Updates", err_msg);
            svcSleepThread(4000000000ULL);
            return false;
        }
    } else {
        AM_CancelCIAInstall(ciaInstallHandle);
        draw_update_notice(text_buf, bottom_target, "Check for Updates", "Error: failed writing to AM handle.");
        svcSleepThread(4000000000ULL);
        return false;
    }
}

bool process_local_update_file(const char* update_path, C2D_TextBuf text_buf, C3D_RenderTarget* bottom_target) {
    // open local .update package
    FILE* f = std::fopen(update_path, "rb");
    if (!f) {
        return false;
    }

    update_manifest_t manifest;
    if (std::fread(&manifest, 1, sizeof(update_manifest_t), f) != sizeof(update_manifest_t)) {
        std::fclose(f);
        draw_update_notice(text_buf, bottom_target, "Auto Update", "Error: failed to read manifest header.");
        svcSleepThread(3000000000ULL);
        return false;
    }

    if (!verify_update_manifest(manifest)) {
        std::fclose(f);
        draw_update_notice(text_buf, bottom_target, "Auto Update", "Error: invalid manifest signature.");
        svcSleepThread(3000000000ULL);
        return false;
    }

    if (manifest.version <= CURRENT_APP_VERSION) {
        std::fclose(f);
        char msg[128];
        std::snprintf(msg, sizeof(msg), "No newer update found (v%lu).", (unsigned long)manifest.version);
        draw_update_notice(text_buf, bottom_target, "Auto Update", msg);
        svcSleepThread(2000000000ULL);
        return false;
    }

    if (manifest.file_size > 10 * 1024 * 1024) {
        std::fclose(f);
        draw_update_notice(text_buf, bottom_target, "Auto Update", "Error: update file size exceeds limit.");
        svcSleepThread(3000000000ULL);
        return false;
    }

    // stream payload to temp CIA while hashing
    FILE* temp_file = std::fopen("sdmc:/3ds/3DSRelay_temp.cia", "wb");
    if (!temp_file) {
        std::fclose(f);
        draw_update_notice(text_buf, bottom_target, "Auto Update", "Error: failed to create temp file.");
        svcSleepThread(3000000000ULL);
        return false;
    }

    sha256_ctx hash_ctx;
    sha256_init(&hash_ctx);

    std::fseek(f, sizeof(update_manifest_t), SEEK_SET);
    uint8_t buf[16384];
    uint32_t remaining = manifest.file_size;
    size_t total_read = 0;
    while (remaining > 0) {
        size_t chunk = remaining > sizeof(buf) ? sizeof(buf) : remaining;
        size_t r = std::fread(buf, 1, chunk, f);
        if (r == 0) break;
        sha256_update(&hash_ctx, buf, r);
        std::fwrite(buf, 1, r, temp_file);
        remaining -= (uint32_t)r;
        total_read += r;
    }

    std::fclose(f);
    std::fclose(temp_file);

    if (total_read != (size_t)manifest.file_size) {
        std::remove("sdmc:/3ds/3DSRelay_temp.cia");
        draw_update_notice(text_buf, bottom_target, "Auto Update", "Error: failed to read update payload.");
        svcSleepThread(3000000000ULL);
        return false;
    }

    sha256_hash_t computed;
    sha256_final(&hash_ctx, computed.bytes);

    if (std::memcmp(computed.bytes, manifest.file_sha256, 32) != 0) {
        std::remove("sdmc:/3ds/3DSRelay_temp.cia");
        draw_update_notice(text_buf, bottom_target, "Auto Update", "Error: SHA-256 mismatch.");
        svcSleepThread(3000000000ULL);
        return false;
    }

    // keep update package on sd to seed it to other peers

    // install payload
    install_cia("sdmc:/3ds/3DSRelay_temp.cia", text_buf, bottom_target);
    return true;
}

// resume sidecars: a partial package and a per-block bitmap so a dropped
// transfer continues instead of restarting
#define UPDATE_PART_PATH   "sdmc:/3ds/3DSRelay.update.part"
#define UPDATE_BITMAP_PATH "sdmc:/3ds/3DSRelay.update.bitmap"

struct resume_header_t {
    uint32_t magic;
    uint32_t version;
    uint32_t file_size;
    uint8_t file_sha256[32];
    uint32_t total_blocks;
};

static inline void bitmap_mark(uint8_t* bm, uint32_t i) { bm[i >> 3] |= (uint8_t)(1u << (i & 7)); }
static inline bool bitmap_get(const uint8_t* bm, uint32_t i) { return (bm[i >> 3] >> (i & 7)) & 1u; }

// load a saved bitmap only when its header and partial file match the manifest
static bool load_resume_state(const update_manifest_t& manifest, uint32_t total_blocks, uint8_t* bitmap, size_t bitmap_bytes) {
    FILE* bf = std::fopen(UPDATE_BITMAP_PATH, "rb");
    if (!bf) return false;
    resume_header_t hdr;
    bool ok = std::fread(&hdr, 1, sizeof(hdr), bf) == sizeof(hdr);
    ok = ok && hdr.magic == 0x55504434 && hdr.version == manifest.version &&
         hdr.file_size == manifest.file_size && hdr.total_blocks == total_blocks &&
         std::memcmp(hdr.file_sha256, manifest.file_sha256, 32) == 0;
    if (ok) {
        ok = std::fread(bitmap, 1, bitmap_bytes, bf) == bitmap_bytes;
    }
    std::fclose(bf);
    if (ok) {
        FILE* pf = std::fopen(UPDATE_PART_PATH, "rb");
        if (!pf) { ok = false; } else { std::fclose(pf); }
    }
    return ok;
}

static void save_resume_state(const update_manifest_t& manifest, uint32_t total_blocks, const uint8_t* bitmap, size_t bitmap_bytes) {
    FILE* bf = std::fopen(UPDATE_BITMAP_PATH, "wb");
    if (!bf) return;
    resume_header_t hdr;
    hdr.magic = 0x55504434;
    hdr.version = manifest.version;
    hdr.file_size = manifest.file_size;
    std::memcpy(hdr.file_sha256, manifest.file_sha256, 32);
    hdr.total_blocks = total_blocks;
    std::fwrite(&hdr, 1, sizeof(hdr), bf);
    std::fwrite(bitmap, 1, bitmap_bytes, bf);
    std::fclose(bf);
}

// query for a newer-version reply, returning the responding node
static bool query_mesh_manifest(NativeNetworkLink& link, update_manifest_t& out_manifest, u16& out_provider, u64 timeout_ms) {
    update_packet_t query;
    std::memset(&query, 0, sizeof(update_packet_t));
    query.type = 0;
    query.block_index = 0xFFFFFFFF;
    udsSendTo(UDS_BROADCAST_NETWORKNODEID, 1, UDS_SENDFLAG_Broadcast, &query, sizeof(update_packet_t));

    u64 start = osGetTime();
    while (aptMainLoop()) {
        hidScanInput();
        if (hidKeysDown() & KEY_B) return false;
        if (osGetTime() - start > timeout_ms) return false;

        packet_t temp_chat;
        link.receive(temp_chat);

        update_packet_t rx;
        u16 node = 0;
        if (link.check_and_pop_update_packet(rx, node)) {
            if (rx.type == 1 && rx.block_index == 0xFFFFFFFF && rx.length == 108) {
                update_manifest_t m;
                std::memcpy(&m, rx.payload, 108);
                if (m.magic == 0x55504434 && m.version > CURRENT_APP_VERSION) {
                    out_manifest = m;
                    out_provider = node;
                    return true;
                }
            }
        }
        svcSleepThread(20000000ULL);
    }
    return false;
}

// windowed, resumable download: tracks a bitmap, re-acquires a peer on stall,
// falls back to single-block for old seeders, keeps the partial for resume
static bool download_update_windowed(NativeNetworkLink& link, update_manifest_t manifest, u16 provider_node, C2D_TextBuf text_buf, C3D_RenderTarget* bottom_target) {
    size_t total_size = 108 + (size_t)manifest.file_size;
    uint32_t total_blocks = (uint32_t)((total_size + UPDATE_BLOCK_SIZE - 1) / UPDATE_BLOCK_SIZE);
    size_t bitmap_bytes = (total_blocks + 7) / 8;

    uint8_t* bitmap = (uint8_t*)std::calloc(1, bitmap_bytes);
    if (!bitmap) {
        draw_update_notice(text_buf, bottom_target, "OTA Update", "Error: out of memory.");
        svcSleepThread(2000000000ULL);
        return false;
    }

    FILE* part_f = NULL;
    if (load_resume_state(manifest, total_blocks, bitmap, bitmap_bytes)) {
        part_f = std::fopen(UPDATE_PART_PATH, "r+b");
    }
    if (!part_f) {
        // fresh download: discard any stale partial and bitmap
        std::memset(bitmap, 0, bitmap_bytes);
        part_f = std::fopen(UPDATE_PART_PATH, "wb+");
    }
    if (!part_f) {
        std::free(bitmap);
        draw_update_notice(text_buf, bottom_target, "OTA Update", "Error: failed to open partial file on SD.");
        svcSleepThread(2000000000ULL);
        return false;
    }

    uint32_t received = 0;
    for (uint32_t i = 0; i < total_blocks; ++i) {
        if (bitmap_get(bitmap, i)) received++;
    }

    bool cancelled = false;
    int dry_windows = 0; // consecutive windows that returned no new block
    char progress_msg[128];

    while (received < total_blocks) {
        uint32_t start = 0;
        while (start < total_blocks && bitmap_get(bitmap, start)) start++;
        if (start >= total_blocks) break;

        uint32_t count = UPDATE_WINDOW_BLOCKS;
        if (start + count > total_blocks) count = total_blocks - start;

        update_packet_t req;
        std::memset(&req, 0, sizeof(update_packet_t));
        if (dry_windows >= 3) {
            // persistent silence: drop to single-block legacy request (old seeders)
            req.type = 0;
            req.block_index = start;
            count = 1;
        } else {
            req.type = 3;
            req.block_index = start;
            req.length = count;
        }
        udsSendTo(provider_node, 1, UDS_SENDFLAG_Default, &req, sizeof(update_packet_t));

        uint32_t got_this_window = 0;
        u64 win_start = osGetTime();
        u64 win_timeout = 400 + (u64)count * 60;
        while (osGetTime() - win_start < win_timeout) {
            hidScanInput();
            if (hidKeysDown() & KEY_B) { cancelled = true; break; }

            packet_t temp_chat;
            link.receive(temp_chat);

            update_packet_t resp;
            u16 node = 0;
            bool drained = false;
            while (link.check_and_pop_update_packet(resp, node)) {
                drained = true;
                if (resp.type == 1 && resp.block_index < total_blocks && !bitmap_get(bitmap, resp.block_index)) {
                    std::fseek(part_f, (long)resp.block_index * UPDATE_BLOCK_SIZE, SEEK_SET);
                    if (std::fwrite(resp.payload, 1, resp.length, part_f) == (size_t)resp.length) {
                        bitmap_mark(bitmap, resp.block_index);
                        received++;
                        got_this_window++;
                        provider_node = node; // lock onto whoever is answering
                    }
                }
            }
            if (got_this_window >= count) break;
            if (!drained) svcSleepThread(3000000ULL);
        }

        if (cancelled) break;

        if (got_this_window == 0) {
            dry_windows++;
            if (dry_windows == 6) {
                // sustained stall: try to re-acquire any peer serving the same update
                draw_update_notice(text_buf, bottom_target, "OTA Update", "Link stalled, re-acquiring peer...");
                update_manifest_t rm;
                u16 rp = 0;
                if (query_mesh_manifest(link, rm, rp, 4000) && rm.version == manifest.version &&
                    std::memcmp(rm.file_sha256, manifest.file_sha256, 32) == 0) {
                    provider_node = rp;
                }
            }
            if (dry_windows >= 30) break; // give up this session, partial is kept
        } else {
            dry_windows = 0;
        }

        std::fflush(part_f);
        save_resume_state(manifest, total_blocks, bitmap, bitmap_bytes);

        std::snprintf(progress_msg, sizeof(progress_msg), "Downloading via UDS...\nBlock %lu of %lu",
            (unsigned long)received, (unsigned long)total_blocks);
        draw_update_notice(text_buf, bottom_target, "OTA Update", progress_msg);
    }

    std::fclose(part_f);
    bool complete = (received >= total_blocks);
    std::free(bitmap);

    if (!complete) {
        // partial + bitmap remain on SD so the next check resumes from here
        const char* msg = cancelled ? "Cancelled. Progress saved, will resume next time."
                                    : "Link lost. Progress saved, will resume next time.";
        draw_update_notice(text_buf, bottom_target, "OTA Update", msg);
        svcSleepThread(2500000000ULL);
        return false;
    }

    // fully assembled: promote the partial to the seed file and verify/install
    std::remove(UPDATE_BITMAP_PATH);
    std::remove("sdmc:/3ds/3DSRelay.update");
    if (std::rename(UPDATE_PART_PATH, "sdmc:/3ds/3DSRelay.update") != 0) {
        draw_update_notice(text_buf, bottom_target, "OTA Update", "Error: failed to finalize update file.");
        svcSleepThread(2000000000ULL);
        return false;
    }

    draw_update_notice(text_buf, bottom_target, "OTA Update", "Download complete! Verifying signature...");
    svcSleepThread(1000000000ULL);
    return process_local_update_file("sdmc:/3ds/3DSRelay.update", text_buf, bottom_target);
}

bool check_mesh_for_update(NativeNetworkLink& link, C2D_TextBuf text_buf, C3D_RenderTarget* bottom_target) {
    bool has_newer_local = false;
    FILE* update_f = std::fopen("sdmc:/3ds/3DSRelay.update", "rb");
    if (update_f) {
        update_manifest_t manifest;
        if (std::fread(&manifest, 1, sizeof(update_manifest_t), update_f) == sizeof(update_manifest_t)) {
            if (manifest.magic == 0x55504434 && manifest.version > CURRENT_APP_VERSION) {
                has_newer_local = true;
            }
        }
        std::fclose(update_f);
    }
    if (has_newer_local) {
        return process_local_update_file("sdmc:/3ds/3DSRelay.update", text_buf, bottom_target);
    }

    bool has_newer_ready = false;
    FILE* ready_f = std::fopen("sdmc:/3ds/3DSRelay_ready.update", "rb");
    if (ready_f) {
        update_manifest_t manifest;
        if (std::fread(&manifest, 1, sizeof(update_manifest_t), ready_f) == sizeof(update_manifest_t)) {
            if (manifest.magic == 0x55504434 && manifest.version > CURRENT_APP_VERSION) {
                has_newer_ready = true;
            }
        }
        std::fclose(ready_f);
    }
    if (has_newer_ready) {
        return process_local_update_file("sdmc:/3ds/3DSRelay_ready.update", text_buf, bottom_target);
    }

    // Verify UDS connection is active before running queries
    if (!link.is_connected()) {
        char ver_str[16];
        format_app_version(CURRENT_APP_VERSION, ver_str, sizeof(ver_str));
        char msg[128];
        std::snprintf(msg, sizeof(msg), "Running %s.\nNo local update found.\nVerify UDS mesh connection is active.", ver_str);
        draw_update_notice(text_buf, bottom_target, "Check for Updates", msg);
        svcSleepThread(3000000000ULL);
        return false;
    }

    draw_update_notice(text_buf, bottom_target, "Check for Updates", "Querying mesh network for updates...");

    // find a peer advertising a newer version (also used to re-acquire on stall)
    update_manifest_t manifest;
    u16 provider_node = 0;
    if (!query_mesh_manifest(link, manifest, provider_node, 5000)) {
        draw_update_notice(text_buf, bottom_target, "Check for Updates", "No newer updates found on mesh network.");
        svcSleepThread(2000000000ULL);
        return false;
    }

    char found_ver[16];
    format_app_version(manifest.version, found_ver, sizeof(found_ver));
    char progress_msg[128];
    std::snprintf(progress_msg, sizeof(progress_msg), "Found update %s!\nDownloading via UDS...", found_ver);
    draw_update_notice(text_buf, bottom_target, "OTA Update", progress_msg);

    // windowed transfer with bitmap-based resume and peer re-acquisition
    return download_update_windowed(link, manifest, provider_node, text_buf, bottom_target);
}

void serve_mesh_update_requests(NativeNetworkLink& link) {
    update_packet_t rx_update;
    u16 src_node = 0;

    while (link.check_and_pop_update_packet(rx_update, src_node)) {
        // type 0 = legacy single block / manifest query, type 3 = batch window request
        if (rx_update.type != 0 && rx_update.type != 3) {
            continue;
        }
        FILE* serve_f = std::fopen("sdmc:/3ds/3DSRelay.update", "rb");
        if (!serve_f) {
            serve_f = std::fopen("sdmc:/3ds/3DSRelay_ready.update", "rb");
        }
        if (!serve_f) {
            continue;
        }

        if (rx_update.type == 0 && rx_update.block_index == 0xFFFFFFFF) {
            // manifest query: send first 108 bytes
            update_packet_t tx_update;
            tx_update.type = 1;
            tx_update.block_index = 0xFFFFFFFF;
            std::fseek(serve_f, 0, SEEK_SET);
            size_t read_bytes = std::fread(tx_update.payload, 1, 108, serve_f);
            tx_update.length = (uint32_t)read_bytes;
            udsSendTo(src_node, 1, UDS_SENDFLAG_Default, &tx_update, sizeof(update_packet_t));
        } else if (rx_update.type == 0) {
            // legacy single-block request kept for peers on the old protocol
            update_packet_t tx_update;
            tx_update.type = 1;
            tx_update.block_index = rx_update.block_index;
            std::fseek(serve_f, (long)rx_update.block_index * UPDATE_BLOCK_SIZE, SEEK_SET);
            size_t read_bytes = std::fread(tx_update.payload, 1, UPDATE_BLOCK_SIZE, serve_f);
            tx_update.length = (uint32_t)read_bytes;
            udsSendTo(src_node, 1, UDS_SENDFLAG_Default, &tx_update, sizeof(update_packet_t));
        } else {
            // batch request: stream a window from one open handle, paced for the recv queue
            uint32_t start = rx_update.block_index;
            uint32_t count = rx_update.length;
            if (count == 0 || count > UPDATE_WINDOW_BLOCKS) {
                count = UPDATE_WINDOW_BLOCKS;
            }
            std::fseek(serve_f, (long)start * UPDATE_BLOCK_SIZE, SEEK_SET);
            for (uint32_t j = 0; j < count; ++j) {
                update_packet_t tx_update;
                tx_update.type = 1;
                tx_update.block_index = start + j;
                size_t read_bytes = std::fread(tx_update.payload, 1, UPDATE_BLOCK_SIZE, serve_f);
                tx_update.length = (uint32_t)read_bytes;
                udsSendTo(src_node, 1, UDS_SENDFLAG_Default, &tx_update, sizeof(update_packet_t));
                if (read_bytes < UPDATE_BLOCK_SIZE) {
                    break; // reached end of file
                }
                svcSleepThread(1500000ULL); // ~1.5ms pacing between packets
            }
        }
        std::fclose(serve_f);
    }
}

void cleanup_mesh_update_port() {
    // Port 2 is no longer used, so this is a no-op
}