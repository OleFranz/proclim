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

void RateLimiter::refill() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(now - last_update);

    // add tokens based on elapsed time
    double new_tokens = (elapsed.count() / 1000000.0) * bytes_per_second;
    tokens = std::min(tokens + new_tokens, (double)burst_size);

    last_update = now;
}

bool RateLimiter::try_consume(uint64_t bytes) {
    std::lock_guard<std::mutex> lock(mutex);

    refill();

    if (tokens >= bytes) {
        tokens -= bytes;
        return true;
    }

    return false;
}


// MARK: ThrottleManager
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

ThrottleManager::ThrottleManager(HANDLE handle)
    : network_handle(handle)
    , running(true) {
}

void ThrottleManager::add_throttle(const ThrottleConfig& config) {
    std::lock_guard<std::mutex> lock(config_mutex);

    if (config.pid != 0) {
        configs[config.pid] = config;
        // create or update rate limiter using emplace with piecewise construction
        auto it = limiters.find(config.pid);
        if (it == limiters.end()) {
            limiters.emplace(
                std::piecewise_construct,
                std::forward_as_tuple(config.pid),
                std::forward_as_tuple(config.bytes_per_second, config.burst_size)
            );
        } else {
            // update existing limiter by erasing and re-creating
            limiters.erase(it);
            limiters.emplace(
                std::piecewise_construct,
                std::forward_as_tuple(config.pid),
                std::forward_as_tuple(config.bytes_per_second, config.burst_size)
            );
        }
    }

    // also add executable based config if specified
    if (!config.executable.empty()) {
        exe_configs[config.executable] = config;
    }
}

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

bool ThrottleManager::should_queue_packet(DWORD pid, uint32_t packet_size) {
    std::lock_guard<std::mutex> lock(config_mutex);

    // check if this pid is throttled directly
    auto it = limiters.find(pid);
    if (it != limiters.end()) {
        // check if we can send immediately
        return !it->second.try_consume(packet_size);
    }

    // check if the executable is throttled
    std::string exe_name = pid_to_executable(pid);
    if (!exe_name.empty()) {
        auto exe_it = exe_configs.find(exe_name);
        if (exe_it != exe_configs.end()) {
            // check if this is a PID-specific config or general executable config
            if (exe_it->second.pid == 0 || exe_it->second.pid == pid) {
                // create limiter for this PID if it doesnt exist
                auto limiter_it = limiters.find(pid);
                if (limiter_it == limiters.end()) {
                    limiters.emplace(
                        std::piecewise_construct,
                        std::forward_as_tuple(pid),
                        std::forward_as_tuple(exe_it->second.bytes_per_second, exe_it->second.burst_size)
                    );
                    it = limiters.find(pid);
                } else {
                    it = limiter_it;
                }
                return !it->second.try_consume(packet_size);
            }
        }
    }

    return false;  // not throttled
}

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

            // calculate how long packet was queued
            auto now = std::chrono::steady_clock::now();
            auto queued_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - packet.enqueue_time).count();
        } else {
            // put packet back in queue and wait
            {
                std::lock_guard<std::mutex> lock(queue_mutex);
                packet_queue.push(std::move(packet));
            }

            // sleep for a portion of the wait time
            auto sleep_time = std::min(wait_time, std::chrono::milliseconds(10));
            std::this_thread::sleep_for(sleep_time);
        }
    }
}

void ThrottleManager::stop() {
    running = false;
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