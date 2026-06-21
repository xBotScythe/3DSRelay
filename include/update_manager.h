#ifndef UPDATE_MANAGER_H
#define UPDATE_MANAGER_H

#include "network.h"

#include <citro2d.h>

class NativeNetworkLink;

void draw_update_notice(C2D_TextBuf text_buf, C3D_RenderTarget* bottom_target, const char* title, const char* body);
bool install_cia(const char* cia_path, C2D_TextBuf text_buf, C3D_RenderTarget* bottom_target);
bool process_local_update_file(const char* update_path, C2D_TextBuf text_buf, C3D_RenderTarget* bottom_target);
bool check_mesh_for_update(NativeNetworkLink& link, C2D_TextBuf text_buf, C3D_RenderTarget* bottom_target);
void serve_mesh_update_requests(NativeNetworkLink& link);
void cleanup_mesh_update_port();

#endif // UPDATE_MANAGER_H
