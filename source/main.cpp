// main.cpp
// entry point and hardware lifecycle execution loop for 3dsrelay

#include <3ds.h>
#include <citro2d.h>
#include <cstdio>
#include <cstring>
#include <malloc.h>
#include <unistd.h>

#include "pow.h"
#include "ringbuffer.h"
#include "network_impl.h"
#include "chacha20.h"
#include "tweetnacl.h"
#include "smaz.h"
#include "crypto_utils.h"
#include "config_store.h"
#include "ui_rendering.h"
#include "update_manager.h"
#include "qr_scan.h"
extern "C" {
    u32 __stacksize__ = 0x40000;
}

void aptIgnoreSleepMode() {
    aptSetSleepAllowed(false);
}

void gspSetLcdForceBlack(bool black) {
    GSPGPU_SetLcdForceBlack(black ? 1 : 0);
}

aptHookCookie hook_cookie;
static volatile bool passphrase_prompt_active = false;
static volatile bool lid_closed = false;

void handle_apt_hook(APT_HookType hook, void* param) {
    if (hook == APTHOOK_ONSLEEP) {
        // lid closed: blank screens to save power; the foreground app keeps
        // running and relaying. no sysmodule, so this is not background routing
        lid_closed = true;
        gspSetLcdForceBlack(true);
    } else if (hook == APTHOOK_ONWAKEUP) {
        // restore screens and force lock status when lid is opened
        lid_closed = false;
        gspSetLcdForceBlack(false);
        // skip lock trigger when keyboard activity causes wakeup events to prevent mid-entry lockout
        if (!passphrase_prompt_active) {
            system_unlocked = false;
            failed_unlock_attempts = 0;
            reset_unlock_input();
        }
    }
}

config_t config;

struct mining_task_t {
    bool active;
    packet_t packet;
    uint32_t current_nonce;
    uint32_t difficulty;
};

static mining_task_t active_mining_task = { false, {}, 0, 8 };

// outbound handshakes queued for the single pow miner
static uint8_t handshake_queue[8][32];
static int handshake_queue_len = 0;

static void enqueue_handshake(const uint8_t pk[32]) {
    for (int i = 0; i < handshake_queue_len; ++i) {
        if (std::memcmp(handshake_queue[i], pk, 32) == 0) {
            return;
        }
    }
    if (handshake_queue_len < 8) {
        std::memcpy(handshake_queue[handshake_queue_len++], pk, 32);
    }
}

static void send_handshake_to_contact(const uint8_t recipient_pk[32], uint32_t difficulty) {
    if (active_mining_task.active) {
        return;
    }
    packet_t tx_packet;
    tx_packet.ver = 2;
    tx_packet.ttl = 4;
    tx_packet.nonce = 0;
    std::memset(tx_packet.ephemeral_pk, 0, 32);
    std::memset(tx_packet.encrypted_payload, 0, ENCRYPTED_PAYLOAD_SIZE);

    if (create_handshake_packet(tx_packet, recipient_pk, config.user_alias, static_pk_sign, static_sk_sign)) {
        active_mining_task.packet = tx_packet;
        active_mining_task.current_nonce = 0;
        active_mining_task.difficulty = difficulty;
        active_mining_task.active = true;
    }
}


static bool should_process_update(const char* path, uint32_t current_version) {
    FILE* f = std::fopen(path, "rb");
    if (!f) return false;
    update_manifest_t manifest;
    size_t read_bytes = std::fread(&manifest, 1, sizeof(update_manifest_t), f);
    std::fclose(f);
    if (read_bytes == sizeof(update_manifest_t)) {
        return (manifest.magic == 0x55504434 && manifest.version > current_version);
    }
    return false;
}


int main(int argc, char* argv[]) {
    gfxInitDefault();
    C3D_Init(C3D_DEFAULT_CMDBUF_SIZE);
    C2D_Init(C2D_DEFAULT_MAX_OBJECTS);
    C2D_Prepare();
    amInit();

    // keep the foreground app awake with the lid closed so it can keep
    // relaying; only works while this app is the running title
    aptSetSleepAllowed(false);

    C3D_RenderTarget* top_target = C2D_CreateScreenTarget(GFX_TOP, GFX_LEFT);
    C3D_RenderTarget* bottom_target = C2D_CreateScreenTarget(GFX_BOTTOM, GFX_LEFT);

    C2D_TextBuf text_buf = C2D_TextBufNew(4096);

    aptHook(&hook_cookie, handle_apt_hook, NULL);

    NativeNetworkLink link;
    if (!link.init()) {
        // fail silently or diagnostic facade remains
    }

    PacketRingBuffer buffer;
    SignatureCache sig_cache;
    // the packet store is encrypted with the at-rest keys, so it loads at
    // unlock; saves are gated on keys_derived so locked relaying can't clobber
    // it with an empty buffer

    if (!load_config(config) || config.unlock_sequence_len < 1 || config.unlock_sequence_len > 16) {
        initialize_default_config(config);
    }

    uint32_t difficulty = 8;
    int fake_sector = 0;
    bool prev_system_unlocked = false;
    u64 duty_cycle_start = 0;
    const u64 DUTY_ACTIVE_MS = 5000;
    const u64 DUTY_IDLE_MS = 45000;
    u64 last_update_check = 0;
    const u64 UPDATE_CHECK_INTERVAL_MS = 180000;
    size_t prev_buffer_size = 999999;
    int frame_counter = 0;
    bool force_redraw = true;
    char prev_link_status[128] = "";
    int selected_menu_item = 0;
    int app_state = 0; // 0 = main menu, 1 = pattern setup, 2 = settings, 3 = show pk, 4 = select recipient, 5 = add contact, 6 = incoming request
    int return_app_state = 0; // state to restore after handling an incoming request
    u64 last_handshake_resend = 0;
    const u64 HANDSHAKE_RESEND_MS = 8000;
    // cap resends so a one-sided add stops mining handshakes
    int handshake_attempts[5] = {0};
    const int HANDSHAKE_MAX_ATTEMPTS = 12;
    int temp_selected_idx = 0;
    
    uint32_t temp_seq[16];
    size_t temp_seq_len = 0;

    while (aptMainLoop()) {
        hidScanInput();
        uint32_t keys_down = hidKeysDown();

        
        if (system_unlocked != prev_system_unlocked) {
            force_redraw = true;
            prev_system_unlocked = system_unlocked;
        }
        if (buffer.size() != prev_buffer_size) {
            force_redraw = true;
            prev_buffer_size = buffer.size();
        }
        
        if (keys_down & KEY_START) {
            if (app_state == 1) {
                if (temp_seq_len > 0) {
                    // hash the new sequence before storing
                    config.magic = CONFIG_MAGIC_V6;
                    secure_random_bytes(config.unlock_salt, sizeof(config.unlock_salt));
                    config.unlock_sequence_len = temp_seq_len;
                    hash_unlock_sequence(temp_seq, temp_seq_len, config.unlock_hash, config.unlock_salt, sizeof(config.unlock_salt));
                    save_config(config);
                    app_state = 0;
                    force_redraw = true;
                }
            } else {
                break;
            }
        }

        char current_link_status[128] = "";
        link.get_status_info(current_link_status, sizeof(current_link_status));
        if (std::strcmp(current_link_status, prev_link_status) != 0) {
            force_redraw = true;
            std::strcpy(prev_link_status, current_link_status);
        }

        if (!system_unlocked) {
            if (keys_down & KEY_SELECT) {
                reset_unlock_input();
            }
            uint32_t unlock_key = extract_unlock_key(keys_down);
            if (unlock_key != 0) {
                process_unlock_input(unlock_key, config);
            }
        } else {
            if (system_unlocked && !keys_derived) {
                char alias_buf[16];
                std::memset(alias_buf, 0, sizeof(alias_buf));
                SwkbdState alias_swkbd;
                swkbdInit(&alias_swkbd, SWKBD_TYPE_NORMAL, 1, 15);
                swkbdSetHintText(&alias_swkbd, "Enter alias...");
                SwkbdButton alias_btn = swkbdInputText(&alias_swkbd, alias_buf, sizeof(alias_buf));
                if (alias_btn != SWKBD_BUTTON_RIGHT || std::strlen(alias_buf) == 0) {
                    system_unlocked = false;
                    continue;
                }
                std::snprintf(config.user_alias, sizeof(config.user_alias), "%s", alias_buf);
                std::memset(alias_buf, 0, sizeof(alias_buf));

                SwkbdState pass_swkbd;
                swkbdInit(&pass_swkbd, SWKBD_TYPE_NORMAL, 2, -1);
                swkbdSetHintText(&pass_swkbd, "Enter passphrase...");
                char passphrase_buf[64];
                std::memset(passphrase_buf, 0, sizeof(passphrase_buf));
                passphrase_prompt_active = true;
                SwkbdButton pass_btn = swkbdInputText(&pass_swkbd, passphrase_buf, sizeof(passphrase_buf));
                passphrase_prompt_active = false;
                if (pass_btn == SWKBD_BUTTON_RIGHT && std::strlen(passphrase_buf) > 0) {
                    if (derive_keys_from_passphrase(config.user_alias, passphrase_buf, config)) {
                        system_unlocked = true;
                        save_config(config);
                        load_contacts_from_file();
                        buffer.load_from_file("sdmc:/3ds/3dsrelay.packets", atrest_enc, atrest_mac);

                        // auto-install signed update packages if present
                        if (should_process_update("sdmc:/3ds/3DSRelay.update", CURRENT_APP_VERSION)) {
                            process_local_update_file("sdmc:/3ds/3DSRelay.update", text_buf, bottom_target);
                        } else if (should_process_update("sdmc:/3ds/3DSRelay_ready.update", CURRENT_APP_VERSION)) {
                            process_local_update_file("sdmc:/3ds/3DSRelay_ready.update", text_buf, bottom_target);
                        }
                    } else {
                        system_unlocked = false;
                        reset_unlock_input();
                    }
                    std::memset(passphrase_buf, 0, sizeof(passphrase_buf));
                } else {
                    system_unlocked = false;
                    reset_unlock_input();
                    std::memset(passphrase_buf, 0, sizeof(passphrase_buf));
                }
                force_redraw = true;
                continue;
            }
            if (app_state == 0) {
                if (keys_down & KEY_DDOWN) {
                    selected_menu_item = (selected_menu_item + 1) % 6;
                    force_redraw = true;
                }
                if (keys_down & KEY_DUP) {
                    selected_menu_item = (selected_menu_item + 5) % 6;
                    force_redraw = true;
                }
                if (keys_down & KEY_A) {
                    if (selected_menu_item == 0) {
                        // only confirmed (mutually handshaked) contacts can receive messages
                        if (contact_count > 0 && contact_list[selected_contact_idx].active && contact_list[selected_contact_idx].confirmed) {
                            SwkbdState swkbd;
                            swkbdInit(&swkbd, SWKBD_TYPE_NORMAL, 2, -1);
                            swkbdSetHintText(&swkbd, "Enter message to send...");
                            char text_buf_sw[64];
                            std::memset(text_buf_sw, 0, sizeof(text_buf_sw));
                            SwkbdButton button = swkbdInputText(&swkbd, text_buf_sw, sizeof(text_buf_sw));
                            if (button == SWKBD_BUTTON_RIGHT && std::strlen(text_buf_sw) > 0 && keys_derived) {
                                if (active_mining_task.active) {
                                    force_redraw = true;
                                    continue;
                                }
                                packet_t tx_packet;
                                tx_packet.ver = 1;
                                tx_packet.ttl = 4;
                                tx_packet.nonce = 0;
                                std::memset(tx_packet.ephemeral_pk, 0, 32);
                                std::memset(tx_packet.encrypted_payload, 0, ENCRYPTED_PAYLOAD_SIZE);
                                
                                bool enc_res = encrypt_message_packet(
                                    tx_packet, 
                                    text_buf_sw, 
                                    contact_list[selected_contact_idx].pk_box, 
                                    static_sk_box
                                );
                                
                                if (enc_res) {
                                    active_mining_task.packet = tx_packet;
                                    active_mining_task.current_nonce = 0;
                                    active_mining_task.difficulty = difficulty;
                                    active_mining_task.active = true;
                                }
                            }
                        } else {
                            // no confirmed recipient: tell the user instead of doing nothing
                            draw_update_notice(text_buf, bottom_target, "Compose Private Msg", "Select a confirmed contact first.");
                            svcSleepThread(1200000000ULL);
                        }
                        force_redraw = true;
                    } else if (selected_menu_item == 1) {
                        SwkbdState swkbd;
                        swkbdInit(&swkbd, SWKBD_TYPE_NORMAL, 2, -1);
                        swkbdSetHintText(&swkbd, "Enter broadcast message...");
                        char text_buf_sw[128];
                        std::memset(text_buf_sw, 0, sizeof(text_buf_sw));
                        SwkbdButton button = swkbdInputText(&swkbd, text_buf_sw, sizeof(text_buf_sw));
                        if (button == SWKBD_BUTTON_RIGHT && std::strlen(text_buf_sw) > 0 && keys_derived) {
                            if (active_mining_task.active) {
                                force_redraw = true;
                                continue;
                            }
                            packet_t tx_packet;
                            std::memset(&tx_packet, 0, sizeof(tx_packet));
                            tx_packet.ver = 3; // Broadcast
                            tx_packet.ttl = 4;
                            tx_packet.nonce = 0;
                            
                            std::memcpy(tx_packet.ephemeral_pk, static_pk_sign, 32);
                            
                            uint8_t payload[PLAINTEXT_PAYLOAD_SIZE];
                            std::memset(payload, 0, sizeof(payload));
                            payload[0] = 'B';
                            payload[1] = 'C';
                            std::memcpy(payload + 2, static_pk_box, 32);
                            std::snprintf((char*)(payload + 34), 16, "%s", config.user_alias);
                            
                            char compressed[128];
                            std::memset(compressed, 0, sizeof(compressed));
                            int comp_len = smaz_compress(text_buf_sw, std::strlen(text_buf_sw), compressed, sizeof(compressed));
                            if (comp_len >= 0 && comp_len <= 53) {
                                payload[114] = (uint8_t)comp_len;
                                std::memcpy(payload + 115, compressed, comp_len);
                                
                                sign_broadcast_data(payload, 115 + comp_len, static_sk_sign);
                                
                                std::memcpy(tx_packet.encrypted_payload, payload, PLAINTEXT_PAYLOAD_SIZE);
                                
                                active_mining_task.packet = tx_packet;
                                active_mining_task.current_nonce = 0;
                                active_mining_task.difficulty = difficulty;
                                active_mining_task.active = true;
                            }
                        }
                        force_redraw = true;
                    } else if (selected_menu_item == 2) {
                        app_state = 4; // select recipient
                        temp_selected_idx = selected_contact_idx;
                        force_redraw = true;
                    } else if (selected_menu_item == 3) {
                        app_state = 5; // add contact
                        selected_menu_item = 0;
                        force_redraw = true;
                    } else if (selected_menu_item == 4) {
                        app_state = 3; // show public key
                        force_redraw = true;
                    } else if (selected_menu_item == 5) {
                        app_state = 2; // system settings
                        selected_menu_item = 0;
                        force_redraw = true;
                    }
                }
            } else if (app_state == 2) {
                // system settings navigation
                if (keys_down & KEY_DDOWN) {
                    selected_menu_item = (selected_menu_item + 1) % 5;
                    force_redraw = true;
                }
                if (keys_down & KEY_DUP) {
                    selected_menu_item = (selected_menu_item + 4) % 5;
                    force_redraw = true;
                }
                if (keys_down & KEY_A) {
                    if (selected_menu_item == 0) {
                        C2D_TextBufClear(text_buf);
                        C3D_FrameBegin(C3D_FRAME_SYNCDRAW);
                        C2D_TargetClear(bottom_target, C2D_Color32(11, 12, 16, 255));
                        C2D_SceneBegin(bottom_target);
                        draw_bottom_screen_system_settings(text_buf, selected_menu_item);
                        draw_text(text_buf, "Synchronizing...", 12, 218, 0.40f, C2D_Color32(0, 255, 210, 255));
                        C3D_FrameEnd(0);

                        for (size_t i = 0; i < buffer.size(); ++i) {
                            packet_t p;
                            if (buffer.get_at(i, p) && p.ttl > 0) {
                                link.broadcast(p);
                            }
                        }
                        svcSleepThread(1000000000ULL);
                        force_redraw = true;
                    } else if (selected_menu_item == 1) {
                        app_state = 1;
                        temp_seq_len = 0;
                        std::memset(temp_seq, 0, sizeof(temp_seq));
                        force_redraw = true;
                    } else if (selected_menu_item == 2) {
                        check_mesh_for_update(link, text_buf, bottom_target);
                        force_redraw = true;
                    } else if (selected_menu_item == 3) {
                        wipe_runtime_secrets(buffer);
                        system_unlocked = false;
                        app_state = 0;
                        selected_menu_item = 0;

                        C2D_TextBufClear(text_buf);
                        C3D_FrameBegin(C3D_FRAME_SYNCDRAW);
                        C2D_TargetClear(bottom_target, C2D_Color32(11, 12, 16, 255));
                        C2D_SceneBegin(bottom_target);
                        draw_bottom_screen_locked(text_buf, fake_sector);
                        draw_text(text_buf, "PANIC WIPE EXECUTED", 12, 218, 0.40f, C2D_Color32(255, 82, 82, 255));
                        C3D_FrameEnd(0);
                        svcSleepThread(1000000000ULL);
                        force_redraw = true;
                    } else if (selected_menu_item == 4) {
                        // lock & exit: scrub ram, keep the encrypted files, then quit
                        scrub_runtime_secrets(buffer);
                        break;
                    }
                }
                if (keys_down & KEY_B) {
                    app_state = 0;
                    selected_menu_item = 5;
                    force_redraw = true;
                }
            } else if (app_state == 1) {
                // pattern setup recording inputs
                uint32_t recorded_key = extract_unlock_key(keys_down);
                if (recorded_key != 0 && temp_seq_len < 16) {
                    temp_seq[temp_seq_len++] = recorded_key;
                    force_redraw = true;
                }
                if (keys_down & KEY_SELECT) {
                    app_state = 2; // cancel setup
                    selected_menu_item = 1;
                    force_redraw = true;
                }
            } else if (app_state == 3) {
                if (keys_down & KEY_B) {
                    app_state = 0; // exit show pk
                    selected_menu_item = 3;
                    force_redraw = true;
                }
            } else if (app_state == 4) {
                // select recipient app menu navigation
                if (keys_down & KEY_DDOWN) {
                    temp_selected_idx = (temp_selected_idx + 1) % 5;
                    force_redraw = true;
                }
                if (keys_down & KEY_DUP) {
                    temp_selected_idx = (temp_selected_idx + 4) % 5;
                    force_redraw = true;
                }
                if (keys_down & KEY_A) {
                    // pending contacts stay unselectable until the handshake is mutual
                    if (contact_list[temp_selected_idx].active && contact_list[temp_selected_idx].confirmed) {
                        selected_contact_idx = temp_selected_idx;
                        app_state = 0;
                        selected_menu_item = 1;
                    }
                    force_redraw = true;
                }
                if (keys_down & KEY_B) {
                    app_state = 0; // return to menu
                    selected_menu_item = 1;
                    force_redraw = true;
                }
            } else if (app_state == 5) {
                // add contact method picker navigation
                if (keys_down & KEY_DDOWN || keys_down & KEY_DUP) {
                    selected_menu_item = (selected_menu_item + 1) % 2;
                    force_redraw = true;
                }
                if (keys_down & KEY_A) {
                    SwkbdState name_swkbd;
                    char name_buf[16] = "";
                    char pk_hex_buf[65] = "";

                    if (selected_menu_item == 0) {
                        // scan qr contact card: signed binary card, or legacy 3DSR1
                        char card_buf[320] = "";
                        if (run_qr_contact_scan(link, text_buf, bottom_target, card_buf, sizeof(card_buf))) {
                            if (std::strncmp(card_buf, "3DSR2:", 6) == 0) {
                                // signature is verified inside add_contact_record
                                if (add_contact_record(NULL, card_buf)) {
                                    const char* box_hex = std::strchr(card_buf + 6, ':'); // after alias
                                    if (box_hex && std::strlen(box_hex + 1) >= 64) {
                                        uint8_t target_pk[32];
                                        hex_to_bytes(box_hex + 1, target_pk, 32);
                                        enqueue_handshake(target_pk);
                                    }
                                }
                            } else {
                                char scanned_alias[16] = "";
                                const char* key_hex = card_buf;
                                if (std::strncmp(card_buf, "3DSR1:", 6) == 0) {
                                    const char* after_prefix = card_buf + 6;
                                    const char* colon = std::strchr(after_prefix, ':');
                                    if (colon && (colon - after_prefix) < 16) {
                                        std::memcpy(scanned_alias, after_prefix, colon - after_prefix);
                                        scanned_alias[colon - after_prefix] = '\0';
                                        key_hex = colon + 1;
                                    } else {
                                        key_hex = after_prefix;
                                    }
                                }
                                if (std::strlen(key_hex) >= 64) {
                                    const char* alias = scanned_alias[0] ? scanned_alias : "Unknown";
                                    if (add_contact_record(alias, key_hex)) {
                                        // pending until the peer reciprocates
                                        uint8_t target_pk[32];
                                        hex_to_bytes(key_hex, target_pk, 32);
                                        enqueue_handshake(target_pk);
                                    }
                                }
                            }
                        }
                        std::memset(card_buf, 0, sizeof(card_buf));
                    } else {
                        // enter contact key manually
                        swkbdInit(&name_swkbd, SWKBD_TYPE_NORMAL, 2, -1);
                        swkbdSetHintText(&name_swkbd, "Enter contact alias...");
                        SwkbdButton name_btn = swkbdInputText(&name_swkbd, name_buf, sizeof(name_buf));

                        if (name_btn == SWKBD_BUTTON_RIGHT && std::strlen(name_buf) > 0) {
                            SwkbdState pk_swkbd;
                            swkbdInit(&pk_swkbd, SWKBD_TYPE_NORMAL, 2, -1);
                            swkbdSetHintText(&pk_swkbd, "Enter 64-char public key hex...");
                            SwkbdButton pk_btn = swkbdInputText(&pk_swkbd, pk_hex_buf, sizeof(pk_hex_buf));

                            if (pk_btn == SWKBD_BUTTON_RIGHT) {
                                if (add_contact_record(name_buf, pk_hex_buf)) {
                                    // pending until the peer reciprocates
                                    uint8_t target_pk[32];
                                    hex_to_bytes(pk_hex_buf, target_pk, 32);
                                    enqueue_handshake(target_pk);
                                }
                            }
                        }
                    }


                    app_state = 0;
                    selected_menu_item = 2;
                    force_redraw = true;
                }
                if (keys_down & KEY_B) {
                    app_state = 0;
                    selected_menu_item = 2;
                    force_redraw = true;
                }
            } else if (app_state == 6) {
                // accept/reject an unsolicited handshake; a contact registers only on mutual consent
                if (incoming_request_count > 0) {
                    bool handled = false;
                    if (keys_down & KEY_A) {
                        std::string hex = bytes_to_hex(incoming_requests[0].pk_box, 32);
                        if (add_contact_record(incoming_requests[0].alias, hex.c_str())) {
                            for (int ci = 0; ci < contact_count; ++ci) {
                                if (contact_list[ci].active && std::memcmp(contact_list[ci].pk_box, incoming_requests[0].pk_box, 32) == 0) {
                                    contact_list[ci].confirmed = true; // both sides have now consented
                                    break;
                                }
                            }
                            save_contacts_to_file();
                            enqueue_handshake(incoming_requests[0].pk_box); // let the peer confirm us too
                        }
                        handled = true;
                    } else if (keys_down & KEY_B) {
                        handled = true; // reject: drop without registering
                    }
                    if (handled) {
                        for (int ri = 1; ri < incoming_request_count; ++ri) {
                            incoming_requests[ri - 1] = incoming_requests[ri];
                        }
                        incoming_request_count--;
                        if (incoming_request_count == 0) {
                            app_state = return_app_state; // back to where the prompt interrupted
                        }
                        force_redraw = true;
                    }
                } else {
                    app_state = 0;
                    force_redraw = true;
                }
            }
        }

        // scan ad-hoc radio and synchronize messages
        packet_t rx_packet;
        if ((system_unlocked || lid_closed) && link.receive(rx_packet)) {
            uint64_t sig = packet_signature(rx_packet);
            if (rx_packet.ttl > 0 && !sig_cache.seen(sig) && verify_packet_pow(rx_packet, difficulty)) {
                sig_cache.mark_seen(sig);
                rx_packet.ttl--;
                if (!buffer.contains(rx_packet)) {
                    buffer.push(rx_packet);
                    link.broadcast(rx_packet);
                    // relaying works while locked; persistence waits for the keys
                    if (keys_derived) {
                        buffer.save_to_file("sdmc:/3ds/3dsrelay.packets", atrest_enc, atrest_mac);
                    }

                    if (system_unlocked && keys_derived) {
                        uint8_t handshake_pk[32];
                        char handshake_alias[32] = "";
                        if (decrypt_handshake_packet(rx_packet, handshake_pk, handshake_alias, sizeof(handshake_alias), static_sk_box)) {
                            int found_idx = -1;
                            for (int ci = 0; ci < contact_count; ++ci) {
                                if (contact_list[ci].active && std::memcmp(contact_list[ci].pk_box, handshake_pk, 32) == 0) {
                                    found_idx = ci;
                                    break;
                                }
                            }
                            if (found_idx >= 0) {
                                // known contact: confirm once and reciprocate; ignore once
                                // confirmed so handshakes stop instead of ping-ponging
                                if (!contact_list[found_idx].confirmed) {
                                    contact_list[found_idx].confirmed = true;
                                    save_contacts_to_file();
                                    enqueue_handshake(handshake_pk);
                                }
                            } else {
                                // unsolicited: queue for accept/reject, dedup against pending
                                bool dup = false;
                                for (int ri = 0; ri < incoming_request_count; ++ri) {
                                    if (std::memcmp(incoming_requests[ri].pk_box, handshake_pk, 32) == 0) {
                                        dup = true;
                                        break;
                                    }
                                }
                                if (!dup && incoming_request_count < 5) {
                                    std::strncpy(incoming_requests[incoming_request_count].alias, handshake_alias, sizeof(incoming_requests[incoming_request_count].alias) - 1);
                                    incoming_requests[incoming_request_count].alias[sizeof(incoming_requests[incoming_request_count].alias) - 1] = '\0';
                                    std::memcpy(incoming_requests[incoming_request_count].pk_box, handshake_pk, 32);
                                    incoming_request_count++;
                                }
                            }
                        }
                    }
                    force_redraw = true;
                }
            }
        }

        // start the next queued handshake once the single pow miner is free
        if (system_unlocked && keys_derived && !active_mining_task.active && handshake_queue_len > 0) {
            uint8_t next_pk[32];
            std::memcpy(next_pk, handshake_queue[0], 32);
            for (int i = 1; i < handshake_queue_len; ++i) {
                std::memcpy(handshake_queue[i - 1], handshake_queue[i], 32);
            }
            handshake_queue_len--;
            send_handshake_to_contact(next_pk, difficulty);
        }

        // Execute active background mining step
        if (active_mining_task.active) {
            bool solved = solve_packet_pow_step(active_mining_task.packet, active_mining_task.difficulty, active_mining_task.current_nonce, 3000);
            force_redraw = true; // keep updating screen with mining progress
            if (solved) {
                link.broadcast(active_mining_task.packet);
                buffer.push(active_mining_task.packet);
                if (keys_derived) {
                    buffer.save_to_file("sdmc:/3ds/3dsrelay.packets", atrest_enc, atrest_mac);
                }
                active_mining_task.active = false;
            }
        }

        // Handle UDS update port serving in main loop
        if (link.is_connected()) {
            serve_mesh_update_requests(link);
        } else {
            cleanup_mesh_update_port();
        }

        // periodic check for background-downloaded updates
        if (system_unlocked && keys_derived) {
            u64 now_uc = osGetTime();
            if (now_uc - last_update_check >= UPDATE_CHECK_INTERVAL_MS) {
                last_update_check = now_uc;
                FILE* ruf = std::fopen("sdmc:/3ds/3DSRelay_ready.update", "rb");
                if (ruf) {
                    std::fclose(ruf);
                    process_local_update_file("sdmc:/3ds/3DSRelay_ready.update", text_buf, bottom_target);
                }
            }
        }

        // resend to unconfirmed contacts so scan order and loss don't stall confirm
        if (system_unlocked && keys_derived) {
            u64 now_hs = osGetTime();
            if (now_hs - last_handshake_resend >= HANDSHAKE_RESEND_MS) {
                last_handshake_resend = now_hs;
                for (int ci = 0; ci < contact_count; ++ci) {
                    if (contact_list[ci].active && !contact_list[ci].confirmed && handshake_attempts[ci] < HANDSHAKE_MAX_ATTEMPTS) {
                        enqueue_handshake(contact_list[ci].pk_box);
                        handshake_attempts[ci]++;
                    }
                }
            }
        }

        // auto-advance to the accept/reject prompt; skip the access-pattern screen
        // so an unlock combo being recorded there is not discarded mid-entry
        if (system_unlocked && incoming_request_count > 0 && app_state != 6 && app_state != 1) {
            return_app_state = app_state;
            app_state = 6;
            force_redraw = true;
        }

        // background sector scanner updates fake animation ticker
        if (frame_counter % 3 == 0) {
            fake_sector += 1;
            if (!system_unlocked) {
                force_redraw = true;
            }
        }

        // bypass graphic rendering when lid is closed for power conservation during passive transit
        // mesh polling remains active in background to relay transit packets
        if (!lid_closed) {
            // execute 2d frame buffer rendering
            if (force_redraw) {
                C2D_TextBufClear(text_buf);
                C3D_FrameBegin(C3D_FRAME_SYNCDRAW);

                // top screen graphics scene
                C2D_TargetClear(top_target, C2D_Color32(11, 12, 16, 255));
                C2D_SceneBegin(top_target);
                if (!system_unlocked) {
                    draw_top_screen_locked(text_buf, fake_sector);
                } else {
                    draw_top_screen(text_buf, buffer, current_link_status);
                }

                // bottom screen graphics scene
                C2D_TargetClear(bottom_target, C2D_Color32(11, 12, 16, 255));
                C2D_SceneBegin(bottom_target);
                if (!system_unlocked) {
                    draw_bottom_screen_locked(text_buf, fake_sector);
                } else {
                    if (app_state == 0) {
                        draw_bottom_screen_menu(text_buf, selected_menu_item);
                    } else if (app_state == 1) {
                        draw_bottom_screen_pattern_setup(text_buf, temp_seq, temp_seq_len);
                    } else if (app_state == 2) {
                        draw_bottom_screen_system_settings(text_buf, selected_menu_item);
                    } else if (app_state == 3) {
                        draw_bottom_screen_show_pk(text_buf);
                    } else if (app_state == 4) {
                        draw_bottom_screen_select_recipient(text_buf, temp_selected_idx);
                    } else if (app_state == 5) {
                        draw_bottom_screen_add_contact(text_buf, selected_menu_item);
                    } else if (app_state == 6) {
                        const char* req_alias = incoming_request_count > 0 ? incoming_requests[0].alias : "";
                        std::string req_fp = incoming_request_count > 0 ? public_key_fingerprint(incoming_requests[0].pk_box) : std::string();
                        draw_bottom_screen_incoming_request(text_buf, req_alias, req_fp.c_str());
                    }
                }

                if (system_unlocked && active_mining_task.active) {
                    char progress_msg[64];
                    std::snprintf(progress_msg, sizeof(progress_msg), "Mining PoW... (try %u)", (unsigned int)active_mining_task.current_nonce);
                    draw_text(text_buf, progress_msg, 12, 218, 0.40f, C2D_Color32(250, 200, 50, 255));
                }

                C3D_FrameEnd(0);
                force_redraw = false;
            }

            gspWaitForVBlank();
        } else {
            // lid closed duty cycle: active window for relay, then long idle sleep
            u64 now_dc = osGetTime();
            u64 phase = (now_dc - duty_cycle_start) % (DUTY_ACTIVE_MS + DUTY_IDLE_MS);
            if (phase < DUTY_ACTIVE_MS) {
                svcSleepThread(50000000ULL);
            } else {
                svcSleepThread(500000000ULL);
            }
        }
        frame_counter++;
    }

    link.shutdown();
    C2D_TextBufDelete(text_buf);
    C2D_Fini();
    C3D_Fini();
    gfxExit();
    amExit();
    return 0;
}
