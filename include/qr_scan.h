// qr_scan.h
// outer camera qr contact card scanning

#ifndef QR_SCAN_H
#define QR_SCAN_H

#include <3ds.h>
#include <citro2d.h>
#include <stddef.h>

class NativeNetworkLink;

// scans outer camera frames for a 3dsr1 contact card payload; the mesh link is
// pumped during scanning so the uds connection is not torn down mid-scan
bool run_qr_contact_scan(NativeNetworkLink& link, C2D_TextBuf text_buf, C3D_RenderTarget* bottom_target, char* card_out, size_t card_out_len);

#endif
