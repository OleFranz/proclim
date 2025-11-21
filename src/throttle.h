#pragma once

#define MAX_PACKET_SIZE 0xFFFF
#define NOMINMAX

#include <unordered_map>
#include <windivert.h>
#include <cstdint>
#include <chrono>
#include <string>
#include <vector>
#include <mutex>
#include <queue>

#include "common.h"
#include "error.h"
#include "utils.h"


// configuration for rate limiting
struct ThrottleConfig {
    DWORD pid = 0;              // pid to throttle (0 for any)
    std::string executable;     // executable name (optional)
    uint64_t bytes_per_second;  // rate limit in bytes/second
    uint64_t burst_size;        // maximum burst size in bytes
    char mode = 's';            // 'u' = upload only, 'd' = download only, 's' = shared, 'i' = individual
};

// packet queue entry
struct QueuedPacket {
    std::vector<uint8_t> data;  // packet data
    WINDIVERT_ADDRESS addr;     // WinDivert address info
    std::chrono::steady_clock::time_point enqueue_time;
    DWORD pid;                  // associated pid
    PacketDirection direction;  // packet direction
};


// token bucket rate limiter
class RateLimiter {
private:
    uint64_t bytes_per_second;
    uint64_t burst_size;
    double tokens;  // current token count in bytes
    std::chrono::steady_clock::time_point last_update;
    std::mutex mutex;

public:
    RateLimiter(uint64_t rate, uint64_t burst);

    // try to consume tokens, returns true if allowed
    bool try_consume(uint64_t bytes);

    // get time until enough tokens are available
    std::chrono::milliseconds time_until_available(uint64_t bytes);

    // refill tokens based on elapsed time
    void refill();
};


// throttle manager
class ThrottleManager {
private:
    // shared limiter (mode 's')
    std::unordered_map<DWORD, RateLimiter> limiters;
    // individual limiters (mode 'i')
    std::unordered_map<DWORD, RateLimiter> upload_limiters;
    std::unordered_map<DWORD, RateLimiter> download_limiters;

    // support multiple configs per PID for separate upload/download rules
    std::unordered_map<DWORD, std::vector<ThrottleConfig>> configs;
    std::unordered_map<std::string, std::vector<ThrottleConfig>> exe_configs;
    std::mutex config_mutex;

    std::queue<QueuedPacket> packet_queue;
    std::mutex queue_mutex;

    HANDLE network_handle;
    bool running;

public:
    ThrottleManager(HANDLE handle);

    // add or update throttle config for a pid
    void add_throttle(const ThrottleConfig& config);

    // remove throttle for a pid and/or executable
    void remove_throttle(DWORD pid);
    void remove_throttle(const std::string& executable);
    void remove_throttle(DWORD pid, const std::string& executable);

    // check if packet should be throttled, queue if needed
    bool should_queue_packet(DWORD pid, uint32_t packet_size, PacketDirection direction);

    // queue a packet for delayed sending
    void queue_packet(const char* packet, UINT packet_len, const WINDIVERT_ADDRESS& addr, DWORD pid, PacketDirection direction);

    // process queued packets
    void process_queue();

    // stop processing
    void stop();

private:
    // helper to get limiter key for a specific config
    std::string get_limiter_key(DWORD pid, const ThrottleConfig& config);
};


// global throttle manager
extern ThrottleManager* g_throttle_manager;

// initialize throttling system
void init_throttle_system(HANDLE network_handle);

// shutdown throttling system
void shutdown_throttle_system();

// thread function for processing queued packets
void packet_queue_processor();