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

// background updater: detect a newer version on the mesh and download it from the
// main loop without blocking. call update_on_peer_connect when a peer joins,
// background_update_tick every loop while connected.
void update_on_peer_connect(NativeNetworkLink& link);
void background_update_tick(NativeNetworkLink& link, C2D_TextBuf text_buf, C3D_RenderTarget* bottom_target);
bool background_update_active();
int background_update_percent();
// true once a downloaded update has installed and the app needs a restart to apply
bool update_pending_restart();

#endif // UPDATE_MANAGER_H
