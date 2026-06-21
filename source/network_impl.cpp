// network_impl.cpp
// implementation of concrete network link interface for emulation and native hardware

#include "network_impl.h"
#include "metadata.h"
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <cstdio>
#include <deque>

namespace {
    struct QueuedUpdatePacket {
        update_packet_t packet;
        u16 src_node;
    };
    static std::deque<QueuedUpdatePacket> update_packet_queue;
}


NativeNetworkLink::NativeNetworkLink() : uds_active_(false), is_hosting_(false), is_connected_(false), wlan_comm_id_(0x48425710) {
    std::strcpy(passphrase_, "meshnetwork passphrase 3dsrelay");
    last_scan_time_ = 0;
    last_state_change_time_ = 0;
    host_timeout_ = 15000;
    init_error_code_ = 0;
    disconnect_strikes_ = 0;
    scan_failures_ = 0;
    last_health_check_time_ = 0;
}

NativeNetworkLink::~NativeNetworkLink() {
    shutdown();
}

bool NativeNetworkLink::init() {
    init_error_code_ = 0;
    uds_active_ = false;

    Result res = udsInit(0x3000, NULL);
    if (R_FAILED(res)) {
        init_error_code_ = res;
        return false;
    }

    // initialize random seed
    std::srand((unsigned int)osGetTime());

    uds_active_ = true;
    is_connected_ = false;
    is_hosting_ = false;
    last_scan_time_ = 0;
    last_state_change_time_ = osGetTime();
    return true;
}

void NativeNetworkLink::broadcast(const packet_t& packet) {
    if (!uds_active_) {
        return;
    }
    update_mesh_state();

    if (is_connected_) {
        // randomized pre-send delay to avoid lockstep collisions in dense exchanges
        svcSleepThread((u64)relay_jitter_us((uint32_t)std::rand()) * 1000ULL);
        udsSendTo(UDS_BROADCAST_NETWORKNODEID, 1, UDS_SENDFLAG_Broadcast, &packet, sizeof(packet_t));
    }
}

bool NativeNetworkLink::receive(packet_t& output_packet) {
    if (!uds_active_) {
        return false;
    }
    // run state machine to verify connection status
    update_mesh_state();

    if (!is_connected_) {
        return false;
    }

    uint8_t temp_buf[2048];
    while (true) {
        size_t actual_size = 0;
        u16 src_node = 0;
        Result res = udsPullPacket(&bind_ctx_, temp_buf, sizeof(temp_buf), &actual_size, &src_node);
        if (R_FAILED(res) || actual_size == 0) {
            break;
        }

        if (actual_size == sizeof(packet_t)) {
            std::memcpy(&output_packet, temp_buf, sizeof(packet_t));
            return true;
        } else if (actual_size == sizeof(update_packet_t)) {
            update_packet_t up_packet;
            std::memcpy(&up_packet, temp_buf, sizeof(update_packet_t));
            push_update_packet(up_packet, src_node);
        }
    }
    return false;
}

Result NativeNetworkLink::receive_raw(void* buf, size_t size, size_t* actual_size, u16* src_node) {
    if (!uds_active_ || !is_connected_) {
        return -1;
    }
    return udsPullPacket(&bind_ctx_, buf, size, actual_size, src_node);
}

bool NativeNetworkLink::check_and_pop_update_packet(update_packet_t& out_packet, u16& out_src_node) {
    if (update_packet_queue.empty()) {
        return false;
    }
    QueuedUpdatePacket qp = update_packet_queue.front();
    update_packet_queue.pop_front();
    out_packet = qp.packet;
    out_src_node = qp.src_node;
    return true;
}

void NativeNetworkLink::push_update_packet(const update_packet_t& packet, u16 src_node) {
    if (update_packet_queue.size() > 50) {
        update_packet_queue.pop_front();
    }
    QueuedUpdatePacket qp;
    qp.packet = packet;
    qp.src_node = src_node;
    update_packet_queue.push_back(qp);
}

void NativeNetworkLink::shutdown() {
    if (uds_active_) {
        if (is_connected_) {
            udsUnbind(&bind_ctx_);
            if (is_hosting_) {
                udsDestroyNetwork();
            } else {
                udsDisconnectNetwork();
            }
        }
        udsExit();
        uds_active_ = false;
        is_connected_ = false;
        is_hosting_ = false;
    }
}

void NativeNetworkLink::teardown_connection() {
    if (is_connected_) {
        udsUnbind(&bind_ctx_);
        if (is_hosting_) {
            udsDestroyNetwork();
        } else {
            udsDisconnectNetwork();
        }
    }
    is_connected_ = false;
    is_hosting_ = false;
    disconnect_strikes_ = 0;
    scan_failures_ = 0;
}

bool NativeNetworkLink::try_scan_and_connect() {
    u32 scan_buf_size = 0x4000;
    void* scan_buf = std::malloc(scan_buf_size);
    if (!scan_buf) return false;

    udsNetworkScanInfo* networks = NULL;
    size_t total_networks = 0;
    Result res = udsScanBeacons(scan_buf, scan_buf_size, &networks, &total_networks, wlan_comm_id_, 0, NULL, false);

    bool connected = false;
    if (R_SUCCEEDED(res) && total_networks > 0) {
        res = udsConnectNetwork(&networks[0].network, passphrase_, std::strlen(passphrase_), &bind_ctx_, UDS_HOST_NETWORKNODEID, UDSCONTYPE_Client, 1, UDS_DEFAULT_RECVBUFSIZE);
        if (R_SUCCEEDED(res)) {
            is_connected_ = true;
            is_hosting_ = false;
            scan_failures_ = 0;
            connected = true;
        }
    }
    std::free(scan_buf);
    return connected;
}

void NativeNetworkLink::update_mesh_state() {
    if (!uds_active_) {
        return;
    }

    u64 current_time = osGetTime();

    if (!is_connected_) {
        if (current_time - last_scan_time_ < 2000) {
            return;
        }
        last_scan_time_ = current_time;

        if (try_scan_and_connect()) {
            last_state_change_time_ = current_time;
            return;
        }

        scan_failures_++;
        if (scan_failures_ >= 2) {
            udsNetworkStruct net_struct;
            udsGenerateDefaultNetworkStruct(&net_struct, wlan_comm_id_, 0, UDS_MAXNODES);
            Result res = udsCreateNetwork(&net_struct, passphrase_, std::strlen(passphrase_), &bind_ctx_, 1, UDS_DEFAULT_RECVBUFSIZE);
            if (R_SUCCEEDED(res)) {
                is_connected_ = true;
                is_hosting_ = true;
                host_timeout_ = 15000 + (std::rand() % 15000);
            }
            scan_failures_ = 0;
            last_state_change_time_ = current_time;
        }
    } else {
        if (current_time - last_health_check_time_ < 1000) {
            return;
        }
        last_health_check_time_ = current_time;

        udsConnectionStatus status;
        Result res = udsGetConnectionStatus(&status);

        // a client alone in the network has lost its host; the status call often
        // still succeeds, so treat being the only node as a dead link
        bool healthy = R_SUCCEEDED(res);
        if (healthy && !is_hosting_ && status.total_nodes <= 1) {
            healthy = false;
        }

        if (!healthy) {
            disconnect_strikes_++;
        } else {
            disconnect_strikes_ = 0;
        }

        if (disconnect_strikes_ >= 5) {
            teardown_connection();
            last_state_change_time_ = current_time;
            return;
        }

        if (is_hosting_ && status.total_nodes <= 1) {
            if (current_time - last_state_change_time_ >= host_timeout_) {
                teardown_connection();
                last_state_change_time_ = current_time;
            }
        } else if (is_hosting_) {
            last_state_change_time_ = current_time;
        }
    }
}

void NativeNetworkLink::get_status_info(char* out_buf, size_t max_len) {
    if (!uds_active_) {
        if (init_error_code_ != 0) {
            snprintf(out_buf, max_len, "uds inactive (init error: 0x%08X)", (unsigned int)init_error_code_);
        } else {
            snprintf(out_buf, max_len, "uds inactive");
        }
        return;
    }

    udsConnectionStatus status;
    Result res = udsGetConnectionStatus(&status);
    if (R_FAILED(res)) {
        snprintf(out_buf, max_len, "error 0x%08X", (unsigned int)res);
        return;
    }

    snprintf(out_buf, max_len, "%s (%s, nodes: %u, status: 0x%X)",
                  is_connected_ ? (is_hosting_ ? "hosting" : "client") : "scanning",
                  uds_active_ ? "active" : "disabled",
                  (unsigned int)status.total_nodes,
                  (unsigned int)status.status);
}
