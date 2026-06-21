// update_manager.cpp
#include "update_manager.h"
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

    // remove original package to avoid re-processing
    std::remove(update_path);

    // proceed with install
    install_cia("sdmc:/3ds/3DSRelay_temp.cia", text_buf, bottom_target);
    return true;
}

bool check_mesh_for_update(C2D_TextBuf text_buf, C3D_RenderTarget* bottom_target) {
    FILE* update_f = std::fopen("sdmc:/3ds/3DSRelay.update", "rb");
    if (update_f) {
        std::fclose(update_f);
        return process_local_update_file("sdmc:/3ds/3DSRelay.update", text_buf, bottom_target);
    }

    FILE* ready_f = std::fopen("sdmc:/3ds/3DSRelay_ready.update", "rb");
    if (ready_f) {
        std::fclose(ready_f);
        return process_local_update_file("sdmc:/3ds/3DSRelay_ready.update", text_buf, bottom_target);
    }

    char msg[96];
    std::snprintf(msg, sizeof(msg), "Running v%lu.%lu.%lu. No update staged.\n"
        "Updates propagate via mesh.",
        CURRENT_APP_VERSION / 100, (CURRENT_APP_VERSION / 10) % 10, CURRENT_APP_VERSION % 10);
    draw_update_notice(text_buf, bottom_target, "Check for Updates", msg);
    svcSleepThread(2000000000ULL);
    return false;
}