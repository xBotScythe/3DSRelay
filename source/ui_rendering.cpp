// ui_rendering.cpp
// 3DS bottom and top screen user interface rendering

#include "ui_rendering.h"
#include "crypto_utils.h"
#include "qrcodegen.h"
#include "config_store.h"
#include <cstdio>
#include <cstring>

// draw text utility using system shared font
void draw_text(C2D_TextBuf buf, const char* str, float x, float y, float scale, u32 color) {
    if (!str || std::strlen(str) == 0) return;
    C2D_Text text;
    C2D_TextParse(&text, buf, str);
    C2D_TextOptimize(&text);
    C2D_DrawText(&text, C2D_WithColor, x, y, 0.5f, scale, scale, color);
}

// draw rect outline using solid rectangles
void draw_rect_outline(float x, float y, float w, float h, float thickness, u32 color) {
    C2D_DrawRectSolid(x, y, 0.5f, w, thickness, color);
    C2D_DrawRectSolid(x, y + h - thickness, 0.5f, w, thickness, color);
    C2D_DrawRectSolid(x, y, 0.5f, thickness, h, color);
    C2D_DrawRectSolid(x + w - thickness, y, 0.5f, thickness, h, color);
}

void draw_top_screen_locked(C2D_TextBuf text_buf, int fake_sector) {
    // header
    C2D_DrawRectSolid(0, 0, 0.5f, 400, 28, C2D_Color32(20, 20, 20, 255));
    draw_text(text_buf, "MMC File System Analyzer v2.41", 12, 6, 0.45f, C2D_Color32(0, 230, 100, 255));
    C2D_DrawRectSolid(0, 28, 0.5f, 400, 1, C2D_Color32(0, 230, 100, 80));

    // fake diagnostics data
    draw_text(text_buf, "Device Mount: /dev/mmcblk0p1 (FAT32)", 12, 38, 0.38f, C2D_Color32(0, 230, 100, 180));
    draw_text(text_buf, "Volume Serial: 4A8F-09E2", 12, 54, 0.38f, C2D_Color32(0, 230, 100, 180));
    
    char sector_info[64];
    std::sprintf(sector_info, "Checking sectors: 0x%08X to 0x%08X", fake_sector, fake_sector + 128);
    draw_text(text_buf, sector_info, 12, 70, 0.38f, C2D_Color32(0, 230, 100, 220));

    // file scan lines
    draw_text(text_buf, "[SCANNING] Directory structures...", 12, 95, 0.38f, C2D_Color32(0, 230, 100, 255));

    int offset = (fake_sector / 20) % 4;
    const char* paths[] = {
        "/Nintendo 3DS/Private/00000000/title.db ... PASS",
        "/Nintendo 3DS/Private/00000000/import.db ... PASS",
        "/Nintendo 3DS/title/00040000/00030800 ... OK",
        "/Nintendo 3DS/extdata/00000000/00000098 ... OK"
    };

    for (int i = 0; i < 4; ++i) {
        float opacity = (i == offset) ? 255.0f : 120.0f;
        draw_text(text_buf, paths[i], 20, 115 + i * 16, 0.35f, C2D_Color32(0, 230, 100, opacity));
    }

    draw_text(text_buf, "Storage health status: 100% (No bad blocks)", 12, 210, 0.38f, C2D_Color32(0, 230, 100, 180));
}

struct dec_cache_entry_t {
    uint32_t nonce;
    uint8_t ephemeral_pk[32];
    char display_str[128];
};

static const int DEC_CACHE_SIZE = 128;
static dec_cache_entry_t dec_cache[DEC_CACHE_SIZE];
static int dec_cache_head = 0;

void clear_decryption_cache() {
    std::memset(dec_cache, 0, sizeof(dec_cache));
    dec_cache_head = 0;
}

static bool lookup_dec_cache(const packet_t& p, char* display_str_out, int max_len) {
    for (int i = 0; i < DEC_CACHE_SIZE; ++i) {
        if (dec_cache[i].nonce == p.nonce && std::memcmp(dec_cache[i].ephemeral_pk, p.ephemeral_pk, 32) == 0) {
            std::strncpy(display_str_out, dec_cache[i].display_str, max_len - 1);
            display_str_out[max_len - 1] = '\0';
            return true;
        }
    }
    return false;
}

static void insert_dec_cache(const packet_t& p, const char* display_str) {
    dec_cache[dec_cache_head].nonce = p.nonce;
    std::memcpy(dec_cache[dec_cache_head].ephemeral_pk, p.ephemeral_pk, 32);
    std::snprintf(dec_cache[dec_cache_head].display_str, sizeof(dec_cache[dec_cache_head].display_str), "%s", display_str);
    dec_cache_head = (dec_cache_head + 1) % DEC_CACHE_SIZE;
}

void draw_top_screen(C2D_TextBuf text_buf, const PacketRingBuffer& buffer, const char* link_status) {
    // top screen header bar disguised as a diagnostics tool
    C2D_DrawRectSolid(0, 0, 0.5f, 400, 28, C2D_Color32(26, 27, 38, 255));
    draw_text(text_buf, "FAT32 Diagnostics Console", 12, 6, 0.55f, C2D_Color32(0, 255, 210, 255));
    char ver_str[16];
    std::snprintf(ver_str, sizeof(ver_str), "v%lu.%lu.%lu",
        CURRENT_APP_VERSION / 100, (CURRENT_APP_VERSION / 10) % 10, CURRENT_APP_VERSION % 10);
    draw_text(text_buf, ver_str, 350, 8, 0.35f, C2D_Color32(154, 160, 166, 255));
    C2D_DrawRectSolid(0, 28, 0.5f, 400, 1, C2D_Color32(0, 255, 210, 80));

    // show recent message list
    size_t start_idx = (buffer.size() > 4) ? (buffer.size() - 4) : 0;
    int line_offset = 0;
    for (size_t i = start_idx; i < buffer.size(); ++i) {
        packet_t p;
        if (buffer.get_at(i, p)) {
            char display_str[128] = "";
            bool cached = lookup_dec_cache(p, display_str, sizeof(display_str));
            if (!cached) {
                char plaintext[128] = "";
                char sender_alias[32] = "";
                bool dec_success = false;

                if (keys_derived) {
                    if (p.ver == 1) {
                        dec_success = decrypt_message_packet(p, plaintext, sizeof(plaintext), sender_alias, sizeof(sender_alias), static_sk_box);
                        if (dec_success) {
                            std::snprintf(display_str, sizeof(display_str), "%s: %s", sender_alias, plaintext);
                        }
                    } else if (p.ver == 2) {
                        uint8_t handshake_pk[32];
                        char handshake_alias[32] = "";
                        if (decrypt_handshake_packet(p, handshake_pk, handshake_alias, sizeof(handshake_alias), static_sk_box)) {
                            bool exists = false;
                            for (int ci = 0; ci < contact_count; ++ci) {
                                if (contact_list[ci].active && std::memcmp(contact_list[ci].pk_box, handshake_pk, 32) == 0) {
                                    exists = true;
                                    std::strncpy(handshake_alias, contact_list[ci].alias, sizeof(handshake_alias) - 1);
                                    break;
                                }
                            }
                            if (exists) {
                                std::snprintf(display_str, sizeof(display_str), "[System: Handshake from %s]", handshake_alias);
                            } else {
                                std::snprintf(display_str, sizeof(display_str), "[System: Handshake from %s]", handshake_alias);
                            }
                            dec_success = true;
                        }
                    } else if (p.ver == 3) {
                        uint8_t sender_pk_box[32];
                        dec_success = verify_broadcast_packet(p, sender_alias, sizeof(sender_alias), plaintext, sizeof(plaintext), sender_pk_box);
                        if (dec_success) {
                            int contact_idx = -1;
                            for (int ci = 0; ci < contact_count; ++ci) {
                                if (contact_list[ci].active && std::memcmp(contact_list[ci].pk_box, sender_pk_box, 32) == 0) {
                                    contact_idx = ci;
                                    break;
                                }
                            }
                            if (contact_idx != -1) {
                                std::snprintf(display_str, sizeof(display_str), "%s [Broadcast]: %s", contact_list[contact_idx].alias, plaintext);
                            } else {
                                bool name_exists = false;
                                for (int ci = 0; ci < contact_count; ++ci) {
                                    if (contact_list[ci].active && std::strcmp(contact_list[ci].alias, sender_alias) == 0) {
                                        name_exists = true;
                                        break;
                                    }
                                }
                                if (name_exists) {
                                    std::string fp = public_key_fingerprint(sender_pk_box);
                                    std::snprintf(display_str, sizeof(display_str), "%s_%.4s [BC]: %s", sender_alias, fp.c_str(), plaintext);
                                } else {
                                    std::snprintf(display_str, sizeof(display_str), "%s [BC]: %s", sender_alias, plaintext);
                                }
                            }
                        }
                    }
                }

                if (!dec_success) {
                    std::string hex_epk = bytes_to_hex(p.ephemeral_pk, 4);
                    std::snprintf(display_str, sizeof(display_str), "[Relayed Encrypted Data: 0x%s...]", hex_epk.c_str());
                }

                insert_dec_cache(p, display_str);
            }

            float y = 32.0f + line_offset * 43.0f;
            C2D_DrawRectSolid(10, y, 0.5f, 380, 38, C2D_Color32(20, 22, 30, 200));
            draw_rect_outline(10, y, 380, 38, 1.0f, C2D_Color32(31, 142, 239, 80));
            C2D_DrawRectSolid(10, y, 0.5f, 3, 38, C2D_Color32(31, 142, 239, 255));

            draw_text(text_buf, display_str, 20, y + 11, 0.45f, C2D_Color32(240, 242, 245, 255));

            char nonce_str[32];
            std::sprintf(nonce_str, "#%lu", (unsigned long)p.nonce);
            draw_text(text_buf, nonce_str, 320, y + 3, 0.35f, C2D_Color32(154, 160, 166, 255));

            line_offset++;
        }
    }

    // bottom status bar layout
    C2D_DrawRectSolid(0, 212, 0.5f, 400, 28, C2D_Color32(26, 27, 38, 255));
    C2D_DrawRectSolid(0, 212, 0.5f, 400, 1, C2D_Color32(255, 255, 255, 20));

    u32 status_dot_color = C2D_Color32(82, 255, 82, 255);
    if (std::strstr(link_status, "Scan") || std::strstr(link_status, "init")) {
        status_dot_color = C2D_Color32(250, 200, 50, 255);
    } else if (std::strstr(link_status, "error") || std::strstr(link_status, "failed")) {
        status_dot_color = C2D_Color32(255, 82, 82, 255);
    }
    C2D_DrawRectSolid(12, 222, 0.5f, 8, 8, status_dot_color);

    char status_line[128];
    std::sprintf(status_line, "Status: %s", link_status);
    draw_text(text_buf, status_line, 26, 218, 0.42f, C2D_Color32(240, 242, 245, 255));
}

void draw_bottom_screen_locked(C2D_TextBuf text_buf, int fake_sector) {
    // diagnostic screen header
    draw_text(text_buf, "FAT32 File System Diagnostics", 12, 10, 0.48f, C2D_Color32(0, 230, 100, 255));
    C2D_DrawRectSolid(10, 26, 0.5f, 300, 1, C2D_Color32(0, 230, 100, 100));

    draw_text(text_buf, "Sector Scan Status:", 12, 35, 0.38f, C2D_Color32(0, 230, 100, 220));

    for (int i = 0; i < 4; ++i) {
        char sect_line[64];
        std::sprintf(sect_line, "Sector 0x%08X: OK", fake_sector + i);
        draw_text(text_buf, sect_line, 12, 55 + i * 16, 0.36f, C2D_Color32(0, 230, 100, 180));
    }





    draw_text(text_buf, "[Running background diagnostics...]", 12, 210, 0.38f, C2D_Color32(0, 230, 100, 255));

    // animated cluster visual block grid
    for (int idx = 0; idx < 100; ++idx) {
        int col = idx % 10;
        int row = idx / 10;
        float bx = 180.0f + col * 13.0f;
        float by = 40.0f + row * 13.0f;

        u32 block_color;
        int current_scanner = (fake_sector / 3) % 100;
        if (idx < current_scanner) {
            block_color = C2D_Color32(0, 180, 80, 255);
        } else if (idx == current_scanner) {
            block_color = C2D_Color32(50, 180, 255, 255);
        } else {
            block_color = C2D_Color32(0, 50, 20, 255);
        }

        C2D_DrawRectSolid(bx, by, 0.5f, 10, 10, block_color);
    }
}

void draw_bottom_screen_menu(C2D_TextBuf text_buf, int selected_item) {
    C2D_DrawRectSolid(0, 0, 0.5f, 320, 28, C2D_Color32(26, 27, 38, 255));
    draw_text(text_buf, "FAT32 Diagnostics Manager", 12, 6, 0.55f, C2D_Color32(0, 255, 210, 255));
    C2D_DrawRectSolid(0, 28, 0.5f, 320, 1, C2D_Color32(0, 255, 210, 80));

    // dynamic compose label displays target contact alias if recipient selected
    char send_label[64];
    std::snprintf(send_label, sizeof(send_label), "Compose Private Msg (%s)", 
                 (contact_list[selected_contact_idx].active) ? contact_list[selected_contact_idx].alias : "none");

    const char* menu_items[6];
    menu_items[0] = send_label;
    menu_items[1] = "Compose Broadcast Msg";
    menu_items[2] = "Select Recipient";
    menu_items[3] = "Add Contact";
    menu_items[4] = "Show My Public Key";
    menu_items[5] = "System Settings";

    for (int i = 0; i < 6; ++i) {
        float y = 32.0f + i * 34.0f;
        if (i == selected_item) {
            C2D_DrawRectSolid(10, y, 0.5f, 300, 30, C2D_Color32(31, 142, 239, 255));
            draw_rect_outline(10, y, 300, 30, 1.5f, C2D_Color32(0, 255, 210, 255));
            draw_text(text_buf, menu_items[i], 20, y + 8, 0.48f, C2D_Color32(255, 255, 255, 255));
        } else {
            C2D_DrawRectSolid(10, y, 0.5f, 300, 30, C2D_Color32(26, 27, 38, 180));
            draw_rect_outline(10, y, 300, 30, 1.0f, C2D_Color32(255, 255, 255, 25));
            draw_text(text_buf, menu_items[i], 20, y + 8, 0.48f, C2D_Color32(190, 195, 200, 255));
        }
    }
}

void draw_bottom_screen_system_settings(C2D_TextBuf text_buf, int selected_item) {
    C2D_DrawRectSolid(0, 0, 0.5f, 320, 28, C2D_Color32(26, 27, 38, 255));
    draw_text(text_buf, "System Settings", 12, 6, 0.55f, C2D_Color32(0, 255, 210, 255));
    C2D_DrawRectSolid(0, 28, 0.5f, 320, 1, C2D_Color32(0, 255, 210, 80));

    const char* menu_items[] = {
        "Synchronize History",
        "Change Access Pattern",
        "Check for Updates",
        "Panic Wipe Staging",
        "Lock & Exit"
    };

    for (int i = 0; i < 5; ++i) {
        float y = 32.0f + i * 34.0f;
        if (i == selected_item) {
            C2D_DrawRectSolid(10, y, 0.5f, 300, 30, C2D_Color32(31, 142, 239, 255));
            draw_rect_outline(10, y, 300, 30, 1.5f, C2D_Color32(0, 255, 210, 255));
            draw_text(text_buf, menu_items[i], 20, y + 8, 0.48f, C2D_Color32(255, 255, 255, 255));
        } else {
            C2D_DrawRectSolid(10, y, 0.5f, 300, 30, C2D_Color32(26, 27, 38, 180));
            draw_rect_outline(10, y, 300, 30, 1.0f, C2D_Color32(255, 255, 255, 25));
            draw_text(text_buf, menu_items[i], 20, y + 8, 0.48f, C2D_Color32(190, 195, 200, 255));
        }
    }
}


static bool qr_build_contact(const char* payload, uint8_t modules[33][33]) {
    uint8_t tempBuffer[qrcodegen_BUFFER_LEN_FOR_VERSION(5)];
    uint8_t qrcode[qrcodegen_BUFFER_LEN_FOR_VERSION(5)];
    
    struct qrcodegen_Segment seg;
    seg.mode = qrcodegen_Mode_BYTE;
    seg.bitLength = 0;
    seg.numChars = std::strlen(payload);
    uint8_t data[128];
    seg.data = data;
    
    for (size_t i = 0; i < std::strlen(payload); i++) {
        data[i] = (uint8_t)payload[i];
    }
    seg.bitLength = std::strlen(payload) * 8;
    
    bool success = qrcodegen_encodeSegments(&seg, 1, qrcodegen_Ecc_LOW, tempBuffer, qrcode);
    if (!success) {
        return false;
    }

    int size = qrcodegen_getSize(qrcode);
    if (size > 33) {
        return false;
    }

    for (int y = 0; y < size; ++y) {
        for (int x = 0; x < size; ++x) {
            modules[y][x] = qrcodegen_getModule(qrcode, x, y) ? 1 : 0;
        }
    }

    return true;
}

void draw_bottom_screen_add_contact(C2D_TextBuf text_buf, int selected_item) {
    C2D_DrawRectSolid(0, 0, 0.5f, 320, 28, C2D_Color32(26, 27, 38, 255));
    draw_text(text_buf, "Add Contact", 12, 6, 0.55f, C2D_Color32(0, 255, 210, 255));
    C2D_DrawRectSolid(0, 28, 0.5f, 320, 1, C2D_Color32(0, 255, 210, 80));

    const char* menu_items[2] = {
        "Scan QR Code",
        "Enter Key Manually"
    };

    for (int i = 0; i < 2; ++i) {
        float y = 32.0f + i * 34.0f;
        if (i == selected_item) {
            C2D_DrawRectSolid(10, y, 0.5f, 300, 30, C2D_Color32(31, 142, 239, 255));
            draw_rect_outline(10, y, 300, 30, 1.5f, C2D_Color32(0, 255, 210, 255));
            draw_text(text_buf, menu_items[i], 20, y + 8, 0.48f, C2D_Color32(255, 255, 255, 255));
        } else {
            C2D_DrawRectSolid(10, y, 0.5f, 300, 30, C2D_Color32(26, 27, 38, 180));
            draw_rect_outline(10, y, 300, 30, 1.0f, C2D_Color32(255, 255, 255, 25));
            draw_text(text_buf, menu_items[i], 20, y + 8, 0.48f, C2D_Color32(190, 195, 200, 255));
        }
    }

    C2D_DrawRectSolid(0, 208, 0.5f, 320, 32, C2D_Color32(26, 27, 38, 255));
    draw_text(text_buf, "A: Select, B: Back", 12, 214, 0.42f, C2D_Color32(255, 255, 255, 255));
}

void draw_bottom_screen_show_pk(C2D_TextBuf text_buf) {
    C2D_DrawRectSolid(0, 0, 0.5f, 320, 28, C2D_Color32(26, 27, 38, 255));
    draw_text(text_buf, "My Public Key", 12, 6, 0.55f, C2D_Color32(0, 255, 210, 255));
    C2D_DrawRectSolid(0, 28, 0.5f, 320, 1, C2D_Color32(0, 255, 210, 80));

    draw_text(text_buf, "Share this contact card:", 12, 38, 0.42f, C2D_Color32(255, 255, 255, 255));

    std::string pk_hex = bytes_to_hex(static_pk_box, 32);
    std::string line1 = pk_hex.substr(0, 32);
    std::string line2 = pk_hex.substr(32, 32);
    std::string fp = public_key_fingerprint(static_pk_box);

    std::string card_full = public_contact_card();
    std::string card_qr = std::string("3DSR1:") + config.user_alias + ":" + bytes_to_hex(static_pk_box, 32);
    uint8_t qr[33][33];
    bool qr_ok = qr_build_contact(card_qr.c_str(), qr);
    C2D_DrawRectSolid(10, 55, 0.5f, 148, 148, C2D_Color32(245, 245, 245, 255));
    draw_rect_outline(10, 55, 148, 148, 1.0f, C2D_Color32(255, 255, 255, 80));
    if (qr_ok) {
        for (int y = 0; y < 33; ++y) {
            for (int x = 0; x < 33; ++x) {
                if (qr[y][x]) {
                    C2D_DrawRectSolid(18 + x * 4, 63 + y * 4, 0.5f, 4, 4, C2D_Color32(15, 15, 15, 255));
                }
            }
        }
    } else {
        draw_text(text_buf, "qr error", 58, 120, 0.45f, C2D_Color32(15, 15, 15, 255));
    }

    draw_text(text_buf, "Fingerprint", 170, 58, 0.36f, C2D_Color32(154, 160, 166, 255));
    draw_text(text_buf, fp.c_str(), 170, 74, 0.42f, C2D_Color32(250, 200, 50, 255));

    C2D_DrawRectSolid(166, 98, 0.5f, 144, 74, C2D_Color32(18, 20, 28, 255));
    draw_rect_outline(166, 98, 144, 74, 1.0f, C2D_Color32(255, 255, 255, 20));

    draw_text(text_buf, line1.substr(0, 16).c_str(), 172, 106, 0.30f, C2D_Color32(0, 255, 210, 255));
    draw_text(text_buf, line1.substr(16, 16).c_str(), 172, 122, 0.30f, C2D_Color32(0, 255, 210, 255));
    draw_text(text_buf, line2.substr(0, 16).c_str(), 172, 138, 0.30f, C2D_Color32(0, 255, 210, 255));
    draw_text(text_buf, line2.substr(16, 16).c_str(), 172, 154, 0.30f, C2D_Color32(0, 255, 210, 255));

    C2D_DrawRectSolid(0, 208, 0.5f, 320, 32, C2D_Color32(26, 27, 38, 255));
    draw_text(text_buf, "Press B to return", 12, 214, 0.42f, C2D_Color32(255, 82, 82, 255));
}

void draw_bottom_screen_select_recipient(C2D_TextBuf text_buf, int temp_selected) {
    C2D_DrawRectSolid(0, 0, 0.5f, 320, 28, C2D_Color32(26, 27, 38, 255));
    draw_text(text_buf, "Select Recipient", 12, 6, 0.55f, C2D_Color32(0, 255, 210, 255));
    C2D_DrawRectSolid(0, 28, 0.5f, 320, 1, C2D_Color32(0, 255, 210, 80));

    for (int i = 0; i < 5; ++i) {
        float y = 32.0f + i * 34.0f;
        if (!contact_list[i].active) {
            C2D_DrawRectSolid(10, y, 0.5f, 300, 30, C2D_Color32(18, 20, 28, 100));
            draw_rect_outline(10, y, 300, 30, 1.0f, C2D_Color32(255, 255, 255, 10));
            draw_text(text_buf, "(empty slot)", 20, y + 8, 0.48f, C2D_Color32(100, 100, 100, 255));
            continue;
        }

        u32 text_color = C2D_Color32(190, 195, 200, 255);
        if (i == temp_selected) {
            C2D_DrawRectSolid(10, y, 0.5f, 300, 30, C2D_Color32(31, 142, 239, 255));
            draw_rect_outline(10, y, 300, 30, 1.5f, C2D_Color32(0, 255, 210, 255));
            text_color = C2D_Color32(255, 255, 255, 255);
        } else {
            C2D_DrawRectSolid(10, y, 0.5f, 300, 30, C2D_Color32(26, 27, 38, 180));
            draw_rect_outline(10, y, 300, 30, 1.0f, C2D_Color32(255, 255, 255, 25));
        }

        char item_text[64];
        const char* status = contact_list[i].confirmed ? "" : " [Pending]";
        if (i == selected_contact_idx) status = contact_list[i].confirmed ? " [Active]" : " [Pending]";
        std::snprintf(item_text, sizeof(item_text), "%.12s%s", contact_list[i].alias, status);
        draw_text(text_buf, item_text, 20, y + 8, 0.48f, text_color);
    }

    C2D_DrawRectSolid(0, 208, 0.5f, 320, 32, C2D_Color32(26, 27, 38, 255));
    draw_text(text_buf, "A: Select, B: Back", 12, 214, 0.42f, C2D_Color32(255, 255, 255, 255));
}

void draw_bottom_screen_pattern_setup(C2D_TextBuf text_buf, const uint32_t* temp_seq, size_t temp_len) {
    C2D_DrawRectSolid(0, 0, 0.5f, 320, 28, C2D_Color32(26, 27, 38, 255));
    draw_text(text_buf, "Access Pattern Setup", 12, 6, 0.55f, C2D_Color32(0, 255, 210, 255));
    C2D_DrawRectSolid(0, 28, 0.5f, 320, 1, C2D_Color32(0, 255, 210, 80));

    draw_text(text_buf, "Press buttons to record sequence", 12, 35, 0.42f, C2D_Color32(255, 255, 255, 255));
    draw_text(text_buf, "(Maximum 16 button presses)", 12, 50, 0.38f, C2D_Color32(154, 160, 166, 255));

    C2D_DrawRectSolid(10, 70, 0.5f, 300, 90, C2D_Color32(18, 20, 28, 255));
    draw_rect_outline(10, 70, 300, 90, 1.0f, C2D_Color32(255, 255, 255, 20));

    for (size_t i = 0; i < temp_len; ++i) {
        int col = i % 8;
        int row = i / 8;
        float px = 16.0f + col * 35.0f;
        float py = 78.0f + row * 38.0f;

        uint32_t key = temp_seq[i];
        const char* name = "";
        u32 pill_color = C2D_Color32(120, 120, 120, 255);

        if (key == KEY_DUP) { name = "U"; pill_color = C2D_Color32(200, 200, 30, 255); }
        else if (key == KEY_DDOWN) { name = "D"; pill_color = C2D_Color32(200, 200, 30, 255); }
        else if (key == KEY_DLEFT) { name = "L"; pill_color = C2D_Color32(200, 200, 30, 255); }
        else if (key == KEY_DRIGHT) { name = "R"; pill_color = C2D_Color32(200, 200, 30, 255); }
        else if (key == KEY_A) { name = "A"; pill_color = C2D_Color32(230, 50, 50, 255); }
        else if (key == KEY_B) { name = "B"; pill_color = C2D_Color32(230, 110, 20, 255); }
        else if (key == KEY_X) { name = "X"; pill_color = C2D_Color32(50, 110, 230, 255); }
        else if (key == KEY_Y) { name = "Y"; pill_color = C2D_Color32(50, 180, 50, 255); }
        else if (key == KEY_L) { name = "SL"; pill_color = C2D_Color32(150, 150, 150, 255); }
        else if (key == KEY_R) { name = "SR"; pill_color = C2D_Color32(150, 150, 150, 255); }

        C2D_DrawRectSolid(px, py, 0.5f, 30, 30, pill_color);
        float text_offset_x = (std::strlen(name) > 1) ? 6.0f : 10.0f;
        draw_text(text_buf, name, px + text_offset_x, py + 7, 0.45f, C2D_Color32(255, 255, 255, 255));
    }

    C2D_DrawRectSolid(0, 180, 0.5f, 320, 60, C2D_Color32(26, 27, 38, 255));
    draw_text(text_buf, "Press START to save pattern", 12, 186, 0.42f, C2D_Color32(82, 255, 82, 255));
    draw_text(text_buf, "Press SELECT to cancel", 12, 208, 0.42f, C2D_Color32(255, 82, 82, 255));
}
