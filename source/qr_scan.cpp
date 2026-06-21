// qr_scan.cpp
// outer camera capture and qr decoding for contact cards

#include "qr_scan.h"
#include "ui_rendering.h"
#include "quirc/quirc.h"
#include <cstdlib>
#include <cstdio>
#include <cstring>

static const int CAM_WIDTH = 400;
static const int CAM_HEIGHT = 240;
static const u32 CAM_BUF_SIZE = CAM_WIDTH * CAM_HEIGHT * sizeof(u16);

struct qr_scan_state {
    Handle event_stop;
    LightEvent event_cam_done;
    LightEvent event_ui_done;
    LightLock mut;
    CondVar cond;

    Thread cam_thread;
    Thread ui_thread;

    volatile int readers_active;
    volatile bool writer_waiting;
    volatile bool writer_active;
    volatile bool frame_updated;

    u16* camera_buffer;
    struct quirc* context;

    C2D_TextBuf text_buf;
    C3D_RenderTarget* bottom_target;
    char qr_debug_msg[128];
};

static void start_read(qr_scan_state* data) {
    LightLock_Lock(&data->mut);
    while (data->writer_waiting || data->writer_active) {
        CondVar_WaitTimeout(&data->cond, &data->mut, 1000000);
    }
    AtomicIncrement(&data->readers_active);
    LightLock_Unlock(&data->mut);
}

static void stop_read(qr_scan_state* data) {
    LightLock_Lock(&data->mut);
    AtomicDecrement(&data->readers_active);
    if (data->readers_active == 0) {
        CondVar_Signal(&data->cond);
    }
    LightLock_Unlock(&data->mut);
}

static void start_write(qr_scan_state* data) {
    LightLock_Lock(&data->mut);
    data->writer_waiting = true;
    while (data->readers_active > 0) {
        CondVar_WaitTimeout(&data->cond, &data->mut, 1000000);
    }
    data->writer_waiting = false;
    data->writer_active = true;
    LightLock_Unlock(&data->mut);
}

static void stop_write(qr_scan_state* data) {
    LightLock_Lock(&data->mut);
    data->writer_active = false;
    CondVar_Broadcast(&data->cond);
    LightLock_Unlock(&data->mut);
}

static bool is_contact_card_payload(const char* payload) {
    if (!payload || std::strncmp(payload, "3DSR1:", 6) != 0) {
        return false;
    }
    const char* after_prefix = payload + 6;
    const char* colon = std::strchr(after_prefix, ':');
    const char* hex = after_prefix;
    if (colon) {
        hex = colon + 1;
    }
    if (std::strlen(hex) < 64) {
        return false;
    }
    for (int i = 0; i < 64; ++i) {
        char c = hex[i];
        bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!ok) {
            return false;
        }
    }
    return true;
}

static void swizzle_camera_frame(C3D_Tex* tex, const u16* camera_buffer) {
    for (u32 y = 0; y < (u32)CAM_HEIGHT; ++y) {
        const u32 src_row = y * CAM_WIDTH;
        for (u32 x = 0; x < (u32)CAM_WIDTH; ++x) {
            const u32 dst_pos = ((((y >> 3) * (512 >> 3) + (x >> 3)) << 6) +
                ((x & 1) | ((y & 1) << 1) | ((x & 2) << 1) | ((y & 2) << 2) | ((x & 4) << 2) | ((y & 4) << 3)));
            ((u16*)tex->data)[dst_pos] = camera_buffer[src_row + x];
        }
    }
}

static void capture_cam_thread(void* arg) {
    qr_scan_state* data = (qr_scan_state*)arg;
    Handle cam_events[3] = {0};
    cam_events[0] = data->event_stop;

    u32 transfer_unit = 0;
    u16* buffer = (u16*)linearAlloc(CAM_BUF_SIZE);

    camInit();
    CAMU_SetSize(SELECT_OUT1, SIZE_CTR_TOP_LCD, CONTEXT_A);
    CAMU_SetOutputFormat(SELECT_OUT1, OUTPUT_RGB_565, CONTEXT_A);
    CAMU_SetFrameRate(SELECT_OUT1, FRAME_RATE_30);
    CAMU_SetNoiseFilter(SELECT_OUT1, true);
    CAMU_SetAutoExposure(SELECT_OUT1, true);
    CAMU_SetAutoWhiteBalance(SELECT_OUT1, true);
    CAMU_Activate(SELECT_OUT1);
    CAMU_GetBufferErrorInterruptEvent(&cam_events[2], PORT_CAM1);
    CAMU_SetTrimming(PORT_CAM1, false);
    CAMU_GetMaxBytes(&transfer_unit, CAM_WIDTH, CAM_HEIGHT);
    CAMU_SetTransferBytes(PORT_CAM1, transfer_unit, CAM_WIDTH, CAM_HEIGHT);
    CAMU_ClearBuffer(PORT_CAM1);
    CAMU_SetReceiving(&cam_events[1], buffer, PORT_CAM1, CAM_BUF_SIZE, (s16)transfer_unit);
    CAMU_StartCapture(PORT_CAM1);

    bool cancel = false;
    while (!cancel) {
        s32 index = 0;
        svcWaitSynchronizationN(&index, cam_events, 3, false, U64_MAX);
        switch (index) {
            case 0:
                cancel = true;
                break;
            case 1:
                svcCloseHandle(cam_events[1]);
                cam_events[1] = 0;

                start_write(data);
                std::memcpy(data->camera_buffer, buffer, CAM_BUF_SIZE);
                data->frame_updated = true;
                stop_write(data);

                CAMU_SetReceiving(&cam_events[1], buffer, PORT_CAM1, CAM_BUF_SIZE, (s16)transfer_unit);
                break;
            case 2:
                svcCloseHandle(cam_events[1]);
                cam_events[1] = 0;

                CAMU_ClearBuffer(PORT_CAM1);
                CAMU_SetReceiving(&cam_events[1], buffer, PORT_CAM1, CAM_BUF_SIZE, (s16)transfer_unit);
                CAMU_StartCapture(PORT_CAM1);
                break;
            default:
                break;
        }
    }

    CAMU_StopCapture(PORT_CAM1);

    bool busy = false;
    while (R_SUCCEEDED(CAMU_IsBusy(&busy, PORT_CAM1)) && busy) {
        svcSleepThread(1000000);
    }

    CAMU_ClearBuffer(PORT_CAM1);
    CAMU_Activate(SELECT_NONE);
    camExit();

    linearFree(buffer);
    for (int i = 1; i < 3; ++i) {
        if (cam_events[i] != 0) {
            svcCloseHandle(cam_events[i]);
            cam_events[i] = 0;
        }
    }

    LightEvent_Signal(&data->event_cam_done);
}

static void update_ui_thread(void* arg) {
    qr_scan_state* data = (qr_scan_state*)arg;
    C3D_Tex tex;
    static const Tex3DS_SubTexture subt3x = {
        CAM_WIDTH, CAM_HEIGHT, 0.0f, 1.0f, 400.0f / 512.0f, 1.0f - (240.0f / 256.0f)
    };

    C3D_TexInit(&tex, 512, 256, GPU_RGB565);
    C3D_TexSetFilter(&tex, GPU_LINEAR, GPU_LINEAR);

    C2D_Sprite preview;
    bool has_preview = false;
    const float preview_scale = 320.0f / 400.0f;

    while (svcWaitSynchronization(data->event_stop, 2000000ULL) == 0x09401BFE) {
        start_read(data);
        if (data->frame_updated) {
            swizzle_camera_frame(&tex, data->camera_buffer);
            data->frame_updated = false;
            has_preview = true;
        }
        stop_read(data);

        C2D_TextBufClear(data->text_buf);
        C3D_FrameBegin(C3D_FRAME_SYNCDRAW);
        C2D_TargetClear(data->bottom_target, C2D_Color32(0, 0, 0, 255));
        C2D_SceneBegin(data->bottom_target);

        // render camera overlay area, draw preview if available
        if (has_preview) {
            C2D_Image img = {&tex, &subt3x};
            C2D_SpriteFromImage(&preview, img);
            C2D_SpriteSetScale(&preview, preview_scale, 1.0f);
            C2D_SpriteSetPos(&preview, 0.0f, 0.0f);
            C2D_DrawSprite(&preview);
        } else {
            C2D_DrawRectSolid(0, 0, 0.5f, 320, 148, C2D_Color32(20, 20, 24, 255));
            draw_text(data->text_buf, "No camera preview", 36, 100, 0.48f, C2D_Color32(180, 180, 180, 255));
        }

        C2D_DrawRectSolid(0, 0, 0.5f, 320, 28, C2D_Color32(26, 27, 38, 220));
        draw_text(data->text_buf, "Scan Contact QR", 12, 6, 0.55f, C2D_Color32(0, 255, 210, 255));
        draw_rect_outline(36, 44, 248, 148, 2.0f, C2D_Color32(0, 255, 210, 220));
        draw_text(data->text_buf, "Point outer camera at QR", 12, 200, 0.38f, C2D_Color32(255, 255, 255, 255));
        draw_text(data->text_buf, "Press A to scan, B to cancel", 12, 214, 0.38f, C2D_Color32(255, 82, 82, 255));
        if (data->qr_debug_msg[0] != '\0') {
            draw_text(data->text_buf, data->qr_debug_msg, 12, 186, 0.32f, C2D_Color32(200, 200, 200, 255));
        }

        C3D_FrameEnd(0);
    }

    C3D_TexDelete(&tex);
    LightEvent_Signal(&data->event_ui_done);
}

static bool start_capture_threads(qr_scan_state* data) {
    // try smaller stack size first, then fall back to larger
    const u32 stack_sizes[] = {0x8000, 0x10000};
    const int prios[] = {0x18, 0x1A, 0x20};
    const int cpus[] = {1, -1};

    for (size_t ci = 0; ci < sizeof(cpus)/sizeof(cpus[0]); ++ci) {
        for (size_t pi = 0; pi < sizeof(prios)/sizeof(prios[0]); ++pi) {
            for (size_t si = 0; si < sizeof(stack_sizes)/sizeof(stack_sizes[0]); ++si) {
                data->cam_thread = threadCreate(capture_cam_thread, data, stack_sizes[si], prios[pi], cpus[ci], false);
                if (!data->cam_thread) {
                    continue;
                }

                data->ui_thread = threadCreate(update_ui_thread, data, stack_sizes[si], prios[pi], cpus[ci], false);
                if (!data->ui_thread) {
                    threadFree(data->cam_thread);
                    data->cam_thread = NULL;
                    continue;
                }

                return true;
            }
        }
    }

    std::snprintf(data->qr_debug_msg, sizeof(data->qr_debug_msg), "thread creation failed");
    LightEvent_Signal(&data->event_cam_done);
    LightEvent_Signal(&data->event_ui_done);
    return false;
}

static bool update_qr_decode(qr_scan_state* data, struct quirc_data* scan_data, char* card_out, size_t card_out_len) {
    int w = 0;
    int h = 0;
    u8* image = quirc_begin(data->context, &w, &h);
    if (!image) {
        std::snprintf(data->qr_debug_msg, sizeof(data->qr_debug_msg), "quirc_begin returned NULL");
        return false;
    }

    start_read(data);
    for (int y = 0; y < h; ++y) {
        const int row = y * w;
        for (int x = 0; x < w; ++x) {
            const int off = row + x;
            const u16 px = data->camera_buffer[off];
            image[off] = (u8)(((((px >> 11) & 0x1F) << 3) + (((px >> 5) & 0x3F) << 2) + ((px & 0x1F) << 3)) / 3);
        }
    }
    stop_read(data);
    quirc_end(data->context);

    int cnt = quirc_count(data->context);
    if (cnt <= 0) {
        std::snprintf(data->qr_debug_msg, sizeof(data->qr_debug_msg), "no codes detected (quirc_count=%d)", cnt);
        return false;
    }

    struct quirc_code code;
    std::memset(&code, 0, sizeof(code));
    quirc_extract(data->context, 0, &code);
    int dec_res = quirc_decode(&code, scan_data);
    if (dec_res != QUIRC_SUCCESS) {
        std::snprintf(data->qr_debug_msg, sizeof(data->qr_debug_msg), "scan failed, try again");
        return false;
    }

    if (!is_contact_card_payload((const char*)scan_data->payload)) {
        std::snprintf(data->qr_debug_msg, sizeof(data->qr_debug_msg), "payload not contact card: %.32s", (const char*)scan_data->payload);
        return false;
    }

    size_t payload_len = std::strlen((const char*)scan_data->payload);
    if (payload_len + 1 > card_out_len) {
        return false;
    }

    std::memcpy(card_out, scan_data->payload, payload_len + 1);
    std::snprintf(data->qr_debug_msg, sizeof(data->qr_debug_msg), "found: %.32s", card_out);
    return true;
}

static void start_qr_scan(qr_scan_state* data, C2D_TextBuf text_buf, C3D_RenderTarget* bottom_target) {
    svcCreateEvent(&data->event_stop, RESET_STICKY);
    LightEvent_Init(&data->event_cam_done, RESET_STICKY);
    LightEvent_Init(&data->event_ui_done, RESET_STICKY);
    LightLock_Init(&data->mut);
    CondVar_Init(&data->cond);

    data->cam_thread = NULL;
    data->ui_thread = NULL;
    data->readers_active = 0;
    data->writer_waiting = false;
    data->writer_active = false;
    data->frame_updated = false;
    data->text_buf = text_buf;
    data->bottom_target = bottom_target;

    // allocate qr context and camera buffer upfront
    data->context = quirc_new();
    quirc_resize(data->context, CAM_WIDTH, CAM_HEIGHT);
    data->camera_buffer = (u16*)calloc(1, CAM_BUF_SIZE);
    data->qr_debug_msg[0] = '\0';
}

static void exit_qr_scan(qr_scan_state* data) {
    svcSignalEvent(data->event_stop);

    LightEvent_Wait(&data->event_ui_done);
    LightEvent_Clear(&data->event_ui_done);
    if (data->ui_thread) {
        threadJoin(data->ui_thread, U64_MAX);
        threadFree(data->ui_thread);
        data->ui_thread = NULL;
    }

    LightEvent_Wait(&data->event_cam_done);
    LightEvent_Clear(&data->event_cam_done);
    if (data->cam_thread) {
        threadJoin(data->cam_thread, U64_MAX);
        threadFree(data->cam_thread);
        data->cam_thread = NULL;
    }

    quirc_destroy(data->context);
    data->context = NULL;
    free(data->camera_buffer);
    data->camera_buffer = NULL;
    svcCloseHandle(data->event_stop);
    data->event_stop = 0;
}

bool run_qr_contact_scan(C2D_TextBuf text_buf, C3D_RenderTarget* bottom_target, char* card_out, size_t card_out_len) {
    if (!card_out || card_out_len < 71) {
        return false;
    }
    card_out[0] = '\0';

    qr_scan_state state;
    std::memset(&state, 0, sizeof(state));
    start_qr_scan(&state, text_buf, bottom_target);

    struct quirc_data* scan_data = (struct quirc_data*)calloc(1, sizeof(struct quirc_data));
    if (!scan_data) {
        exit_qr_scan(&state);
        return false;
    }

    const bool ready = start_capture_threads(&state);
    bool found = false;

    if (!ready) {
        const char* msg = state.qr_debug_msg[0] ? state.qr_debug_msg : "scanner init failed";
        C2D_TextBufClear(text_buf);
        C3D_FrameBegin(C3D_FRAME_SYNCDRAW);
        C2D_TargetClear(bottom_target, C2D_Color32(0, 0, 0, 255));
        C2D_SceneBegin(bottom_target);
        draw_text(text_buf, "Scan Contact QR", 12, 6, 0.55f, C2D_Color32(0, 255, 210, 255));
        draw_rect_outline(36, 44, 248, 148, 2.0f, C2D_Color32(0, 255, 210, 220));
        draw_text(text_buf, msg, 12, 180, 0.38f, C2D_Color32(255, 255, 255, 255));
        draw_text(text_buf, "Press B to continue", 12, 214, 0.38f, C2D_Color32(255, 82, 82, 255));
        C3D_FrameEnd(0);
        gspWaitForVBlank();

        while (aptMainLoop()) {
            hidScanInput();
            if (hidKeysDown() & KEY_B) {
                break;
            }
            svcSleepThread(50 * 1000 * 1000ULL);
        }

        exit_qr_scan(&state);
        std::memset(scan_data, 0, sizeof(struct quirc_data));
        free(scan_data);
        return false;
    }

    if (ready) {
        // draw initial scan ui
        C2D_TextBufClear(text_buf);
        C3D_FrameBegin(C3D_FRAME_SYNCDRAW);
        C2D_TargetClear(bottom_target, C2D_Color32(0, 0, 0, 255));
        C2D_SceneBegin(bottom_target);
        draw_text(text_buf, "Scan Contact QR", 12, 6, 0.55f, C2D_Color32(0, 255, 210, 255));
        draw_rect_outline(36, 44, 248, 148, 2.0f, C2D_Color32(0, 255, 210, 220));
        draw_text(text_buf, "Initializing camera...", 12, 200, 0.38f, C2D_Color32(255, 255, 255, 255));
        C3D_FrameEnd(0);
        gspWaitForVBlank();

        while (aptMainLoop()) {
            hidScanInput();
            uint32_t keys = hidKeysDown();
            if (keys & KEY_B) {
                break;
            }

            // scan when a button pressed
            if (keys & KEY_A) {
                std::snprintf(state.qr_debug_msg, sizeof(state.qr_debug_msg), "Scanning...");
                if (update_qr_decode(&state, scan_data, card_out, card_out_len)) {
                    found = true;
                    break;
                }
                // keep debug message from qr decode
            }

            svcSleepThread(50 * 1000 * 1000ULL);
        }
    }

    exit_qr_scan(&state);
    std::memset(scan_data, 0, sizeof(struct quirc_data));
    free(scan_data);
    return found;
}
