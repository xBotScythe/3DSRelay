#ifndef UPDATE_MANAGER_H
#define UPDATE_MANAGER_H

#include "network.h"

#include <citro2d.h>

void draw_update_notice(C2D_TextBuf text_buf, C3D_RenderTarget* bottom_target, const char* title, const char* body);
bool install_cia(const char* cia_path, C2D_TextBuf text_buf, C3D_RenderTarget* bottom_target);
bool process_local_update_file(const char* update_path, C2D_TextBuf text_buf, C3D_RenderTarget* bottom_target);
bool check_mesh_for_update(C2D_TextBuf text_buf, C3D_RenderTarget* bottom_target);

#endif // UPDATE_MANAGER_H
