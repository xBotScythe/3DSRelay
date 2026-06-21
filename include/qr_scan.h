// qr_scan.h
// outer camera qr contact card scanning

#ifndef QR_SCAN_H
#define QR_SCAN_H

#include <3ds.h>
#include <citro2d.h>
#include <stddef.h>

// scans outer camera frames for a 3dsr1 contact card payload
bool run_qr_contact_scan(C2D_TextBuf text_buf, C3D_RenderTarget* bottom_target, char* card_out, size_t card_out_len);

#endif
