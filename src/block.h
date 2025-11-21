#pragma once

#include <unordered_map>
#include <windivert.h>
#include <cstdint>
#include <chrono>
#include <string>
#include <vector>
#include <mutex>

#include "common.h"
#include "error.h"
#include "utils.h"


// configuration for rate limiting
struct BlockConfig {
    DWORD pid = 0;              // pid to block (0 for any)
    std::string executable;     // executable name (optional)
    char mode = 's';            // 'u' = upload only, 'd' = download only, 's' = shared, 'i' = individual
};


// block manager
class BlockManager {
private:
    // support multiple configs per PID for separate upload/download rules
    std::unordered_map<DWORD, std::vector<BlockConfig>> configs;
    std::unordered_map<std::string, std::vector<BlockConfig>> exe_configs;
    std::mutex config_mutex;

    HANDLE network_handle;
    bool running;

public:
    BlockManager(HANDLE handle);

    // add or update block config for a pid
    void add_block(const BlockConfig& config);

    // remove block for a pid and/or executable
    void remove_block(DWORD pid);
    void remove_block(const std::string& executable);
    void remove_block(DWORD pid, const std::string& executable);

    // check if packet should be blockd, block if needed
    bool should_block_packet(DWORD pid, uint32_t packet_size, PacketDirection direction);

    // block a packet for delayed sending
    void block_packet(const char* packet, UINT packet_len, const WINDIVERT_ADDRESS& addr, DWORD pid, PacketDirection direction);

    // process blockd packets
    void process_block();

    // stop processing
    void stop();

private:
    // helper to get limiter key for a specific config
    std::string get_limiter_key(DWORD pid, const BlockConfig& config);
};


// global block manager
extern BlockManager* g_block_manager;

// initialize blocking system
void init_block_system(HANDLE network_handle);

// shutdown blocking system
void shutdown_block_system();