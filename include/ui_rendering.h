#ifndef UI_RENDERING_H
#define UI_RENDERING_H

#include <3ds.h>
#include <citro2d.h>
#include "ringbuffer.h"

void draw_text(C2D_TextBuf buf, const char* str, float x, float y, float scale, u32 color);
void draw_rect_outline(float x, float y, float w, float h, float thickness, u32 color);

void draw_top_screen_locked(C2D_TextBuf text_buf, int fake_sector);
void draw_top_screen(C2D_TextBuf text_buf, const PacketRingBuffer& buffer, const char* link_status);
void clear_decryption_cache();
void draw_bottom_screen_locked(C2D_TextBuf text_buf, int fake_sector);
void draw_bottom_screen_menu(C2D_TextBuf text_buf, int selected_item);
void draw_bottom_screen_system_settings(C2D_TextBuf text_buf, int selected_item);
void draw_bottom_screen_show_pk(C2D_TextBuf text_buf);
void draw_bottom_screen_add_contact(C2D_TextBuf text_buf, int selected_item);
void draw_bottom_screen_select_recipient(C2D_TextBuf text_buf, int temp_selected);
void draw_bottom_screen_incoming_request(C2D_TextBuf text_buf, const char* alias, const char* fingerprint);
void draw_bottom_screen_pattern_setup(C2D_TextBuf text_buf, const uint32_t* temp_seq, size_t temp_len);

#endif
