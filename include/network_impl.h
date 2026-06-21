// network_impl.h
// concrete network link implementations for host emulation and 3ds hardware

#pragma once

#include "network.h"

class NativeNetworkLink : public NetworkLink {
public:
    NativeNetworkLink();
    virtual ~NativeNetworkLink();

    virtual bool init() override;
    virtual void broadcast(const packet_t& packet) override;
    virtual bool receive(packet_t& output_packet) override;
    virtual void shutdown() override;
    virtual void get_status_info(char* out_buf, size_t max_len) override;
    Result receive_raw(void* buf, size_t size, size_t* actual_size, u16* src_node);
    bool is_connected() const { return is_connected_; }
    bool is_active() const { return uds_active_; }

// UDS update packet queues over channel 1
bool check_and_pop_update_packet(update_packet_t& out_packet, u16& out_src_node);
void push_update_packet(const update_packet_t& packet, u16 src_node);

private:
    bool uds_active_;
    bool is_hosting_;
    bool is_connected_;
    udsBindContext bind_ctx_;
    u32 wlan_comm_id_;
    char passphrase_[64];
    u64 last_scan_time_;
    u64 last_state_change_time_;
    u64 host_timeout_;
    Result init_error_code_;
    int disconnect_strikes_;
    int scan_failures_;
    u64 last_health_check_time_;

    void update_mesh_state();
    void teardown_connection();
    bool try_scan_and_connect();
};
