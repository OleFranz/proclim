#include "throttle.h"

#include <algorithm>
#include <thread>
#include <cstdio>


// MARK: RateLimiter
RateLimiter::RateLimiter(uint64_t rate, uint64_t burst)
    : bytes_per_second(rate)
    , burst_size(burst)
    , tokens(burst)
    , last_update(std::chrono::steady_clock::now()) {
}

// MARK: refill
void RateLimiter::refill() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(now - last_update);

    // add tokens based on elapsed time
    double new_tokens = (elapsed.count() / 1000000.0) * bytes_per_second;
    tokens = std::min(tokens + new_tokens, (double)burst_size);

    last_update = now;
}

// MARK: try_consume
bool RateLimiter::try_consume(uint64_t bytes) {
    std::lock_guard<std::mutex> lock(mutex);

    refill();

    if (tokens >= bytes) {
        tokens -= bytes;
        return true;
    }

    return false;
}

// MARK: time_until_available
std::chrono::milliseconds RateLimiter::time_until_available(uint64_t bytes) {
    std::lock_guard<std::mutex> lock(mutex);

    refill();

    if (tokens >= bytes) {
        return std::chrono::milliseconds(0);
    }

    // calculate how long until we have enough tokens
    double needed = bytes - tokens;
    double seconds = needed / bytes_per_second;

    return std::chrono::milliseconds(static_cast<int64_t>(seconds * 1000));
}


// MARK: ThrottleManager
bool global_mode = false;
bool each_mode = false;
RateLimiter* global_limiter = nullptr;
uint64_t each_rate = 0;
uint64_t each_burst = 0;

ThrottleManager::ThrottleManager(HANDLE handle)
    : network_handle(handle)
    , running(true) {
}

// MARK: add_throttle
void ThrottleManager::add_throttle(const ThrottleConfig& config) {
    std::lock_guard<std::mutex> lock(config_mutex);

    if (config.executable == "global") {
        global_mode = true;
        if (global_limiter) delete global_limiter;
        global_limiter = new RateLimiter(config.bytes_per_second, config.burst_size);
        return;
    }
    if (config.executable == "each") {
        each_mode = true;
        each_rate = config.bytes_per_second;
        each_burst = config.burst_size;
        return;
    }

    if (config.pid != 0) {
        configs[config.pid] = config;
        // always overwrite previous limiter for PID
        limiters.erase(config.pid);
        limiters.emplace(
            std::piecewise_construct,
            std::forward_as_tuple(config.pid),
            std::forward_as_tuple(config.bytes_per_second, config.burst_size)
        );
    }

    // also add/overwrite executable based config if specified
    if (!config.executable.empty()) {
        exe_configs[config.executable] = config;
        // overwrite previous limiter for all matching PIDs
        for (auto it = limiters.begin(); it != limiters.end(); ) {
            DWORD pid = it->first;
            std::string exe_name = pid_to_executable(pid);
            if (exe_name == config.executable) {
                it = limiters.erase(it);
                limiters.emplace(
                    std::piecewise_construct,
                    std::forward_as_tuple(pid),
                    std::forward_as_tuple(config.bytes_per_second, config.burst_size)
                );
                configs[pid] = config;
            } else {
                ++it;
            }
        }
    }
}

// MARK: remove_throttle
void ThrottleManager::remove_throttle(DWORD pid) {
    std::lock_guard<std::mutex> lock(config_mutex);

    limiters.erase(pid);
    configs.erase(pid);
}

void ThrottleManager::remove_throttle(const std::string& executable) {
    std::lock_guard<std::mutex> lock(config_mutex);

    exe_configs.erase(executable);
    for (auto it = limiters.begin(); it != limiters.end();) {
        DWORD pid = it->first;
        auto config_it = configs.find(pid);
        if (config_it != configs.end() && config_it->second.executable == executable) {
            it = limiters.erase(it);
            configs.erase(config_it);
        } else {
            ++it;
        }
    }
}

void ThrottleManager::remove_throttle(DWORD pid, const std::string& executable) {
    remove_throttle(pid);
    remove_throttle(executable);
}

// MARK: should_queue_packet
bool ThrottleManager::should_queue_packet(DWORD pid, uint32_t packet_size) {
    std::lock_guard<std::mutex> lock(config_mutex);

    bool global_throttle = false;
    bool specific_throttle = false;

    // Check global limiter first
    if (global_mode && global_limiter) {
        global_throttle = !global_limiter->try_consume(packet_size);
    }

    // check for PID specific limiter first (overrides "each" and executable)
    auto it = limiters.find(pid);
    if (it != limiters.end()) {
        specific_throttle = !it->second.try_consume(packet_size);
    } else {
        // check for executable specific limiter
        std::string exe_name = pid_to_executable(pid);
        auto exe_it = exe_configs.find(exe_name);
        if (!exe_name.empty() && exe_it != exe_configs.end()) {
            // create limiter for this PID if it doesnt exist
            limiters.emplace(
                std::piecewise_construct,
                std::forward_as_tuple(pid),
                std::forward_as_tuple(exe_it->second.bytes_per_second, exe_it->second.burst_size)
            );
            configs[pid] = exe_it->second;
            it = limiters.find(pid);
            specific_throttle = !it->second.try_consume(packet_size);
        } else if (each_mode && pid != 0 && pid != (DWORD)-1) {
            // if "each" mode, create limiter for PID if not present
            limiters.emplace(
                std::piecewise_construct,
                std::forward_as_tuple(pid),
                std::forward_as_tuple(each_rate ? each_rate : 1024 * 1024, each_burst ? each_burst : (each_rate ? each_rate : 1024 * 1024))
            );
            it = limiters.find(pid);
            specific_throttle = !it->second.try_consume(packet_size);
        }
    }

    // if both global and specific throttles are active, queue if either says to queue
    if (global_mode && global_limiter) {
        return global_throttle || specific_throttle;
    } else {
        return specific_throttle;
    }
}

// MARK: queue_packet
void ThrottleManager::queue_packet(
    const char* packet,
    UINT packet_len,
    const WINDIVERT_ADDRESS& addr,
    DWORD pid
) {
    QueuedPacket queued;
    queued.data.assign(packet, packet + packet_len);
    queued.addr = addr;
    queued.enqueue_time = std::chrono::steady_clock::now();
    queued.pid = pid;

    std::lock_guard<std::mutex> lock(queue_mutex);
    packet_queue.push(std::move(queued));
}

// MARK: process_queue
void ThrottleManager::process_queue() {
    while (running) {
        QueuedPacket packet;
        bool has_packet = false;

        // try to get a packet from the queue
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            if (!packet_queue.empty()) {
                packet = std::move(packet_queue.front());
                packet_queue.pop();
                has_packet = true;
            }
        }

        if (!has_packet) {
            // no packets to process, sleep briefly
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }

        // check if we can send this packet
        bool can_send = false;
        std::chrono::milliseconds wait_time(0);

        {
            std::lock_guard<std::mutex> lock(config_mutex);
            auto it = limiters.find(packet.pid);

            if (it == limiters.end()) {
                // no longer throttled, send immediately
                can_send = true;
            } else {
                // try to consume tokens
                if (it->second.try_consume(packet.data.size())) {
                    can_send = true;
                } else {
                    // need to wait
                    wait_time = it->second.time_until_available(packet.data.size());
                }
            }
        }

        if (can_send) {
            // send the packet
            if (!WinDivertSend(network_handle, packet.data.data(), packet.data.size(), nullptr, &packet.addr)) {
                fprintf(stderr, "WinDivertSend(network) failed: %s\n", send_error_to_string(GetLastError()).c_str());
            }
        } else {
            // put packet back in queue and wait
            {
                std::lock_guard<std::mutex> lock(queue_mutex);
                packet_queue.push(std::move(packet));
            }

            // sleep for a portion of the wait time
            auto sleep_time = std::min(wait_time, std::chrono::milliseconds(1));
            std::this_thread::sleep_for(sleep_time);
        }
    }
}

// MARK: stop
void ThrottleManager::stop() {
    running = false;
    if (global_limiter) {
        delete global_limiter;
        global_limiter = nullptr;
    }
}


// MARK: Throttle functions
ThrottleManager* g_throttle_manager = nullptr;

void init_throttle_system(HANDLE network_handle) {
    if (g_throttle_manager) {
        delete g_throttle_manager;
    }

    g_throttle_manager = new ThrottleManager(network_handle);
}

void shutdown_throttle_system() {
    if (g_throttle_manager) {
        g_throttle_manager->stop();
        delete g_throttle_manager;
        g_throttle_manager = nullptr;
    }
}

void packet_queue_processor() {
    if (g_throttle_manager) {
        g_throttle_manager->process_queue();
    }
}