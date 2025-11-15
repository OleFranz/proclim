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

// MARK: get_limiter_key
std::string ThrottleManager::get_limiter_key(DWORD pid, const ThrottleConfig& config) {
    return std::to_string(pid) + "_" + std::string(1, config.mode);
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
        // add config to the list (dont replace existing ones)
        auto& config_list = configs[config.pid];

        // check if we already have a config with this exact mode
        bool found = false;
        for (auto& existing : config_list) {
            if (existing.mode == config.mode) {
                // update existing config
                existing = config;
                found = true;
                break;
            }
        }

        if (!found) {
            config_list.push_back(config);
        }

        // create appropriate limiter based on mode
        std::string limiter_key = get_limiter_key(config.pid, config);

        if (config.mode == 's') {
            limiters.erase(config.pid);
            limiters.emplace(
                std::piecewise_construct,
                std::forward_as_tuple(config.pid),
                std::forward_as_tuple(config.bytes_per_second, config.burst_size)
            );
        } else if (config.mode == 'i') {
            upload_limiters.erase(config.pid);
            download_limiters.erase(config.pid);
            upload_limiters.emplace(
                std::piecewise_construct,
                std::forward_as_tuple(config.pid),
                std::forward_as_tuple(config.bytes_per_second, config.burst_size)
            );
            download_limiters.emplace(
                std::piecewise_construct,
                std::forward_as_tuple(config.pid),
                std::forward_as_tuple(config.bytes_per_second, config.burst_size)
            );
        } else if (config.mode == 'u') {
            upload_limiters.erase(config.pid);
            upload_limiters.emplace(
                std::piecewise_construct,
                std::forward_as_tuple(config.pid),
                std::forward_as_tuple(config.bytes_per_second, config.burst_size)
            );
        } else if (config.mode == 'd') {
            download_limiters.erase(config.pid);
            download_limiters.emplace(
                std::piecewise_construct,
                std::forward_as_tuple(config.pid),
                std::forward_as_tuple(config.bytes_per_second, config.burst_size)
            );
        }
    }

    // also add executable based config if specified
    if (!config.executable.empty()) {
        auto& exe_config_list = exe_configs[config.executable];

        // check if we already have a config with this exact mode
        bool found = false;
        for (auto& existing : exe_config_list) {
            if (existing.mode == config.mode) {
                existing = config;
                found = true;
                break;
            }
        }

        if (!found) {
            exe_config_list.push_back(config);
        }

        // apply to all matching PIDs
        for (auto& [pid, config_list] : configs) {
            std::string exe_name = pid_to_executable(pid);
            if (exe_name == config.executable) {
                // add/update config for this PID
                bool pid_found = false;
                for (auto& existing : config_list) {
                    if (existing.mode == config.mode) {
                        existing = config;
                        pid_found = true;
                        break;
                    }
                }

                if (!pid_found) {
                    config_list.push_back(config);
                }

                // create limiter
                if (config.mode == 's') {
                    limiters.erase(pid);
                    limiters.emplace(
                        std::piecewise_construct,
                        std::forward_as_tuple(pid),
                        std::forward_as_tuple(config.bytes_per_second, config.burst_size)
                    );
                } else if (config.mode == 'i') {
                    upload_limiters.erase(pid);
                    download_limiters.erase(pid);
                    upload_limiters.emplace(
                        std::piecewise_construct,
                        std::forward_as_tuple(pid),
                        std::forward_as_tuple(config.bytes_per_second, config.burst_size)
                    );
                    download_limiters.emplace(
                        std::piecewise_construct,
                        std::forward_as_tuple(pid),
                        std::forward_as_tuple(config.bytes_per_second, config.burst_size)
                    );
                } else if (config.mode == 'u') {
                    upload_limiters.erase(pid);
                    upload_limiters.emplace(
                        std::piecewise_construct,
                        std::forward_as_tuple(pid),
                        std::forward_as_tuple(config.bytes_per_second, config.burst_size)
                    );
                } else if (config.mode == 'd') {
                    download_limiters.erase(pid);
                    download_limiters.emplace(
                        std::piecewise_construct,
                        std::forward_as_tuple(pid),
                        std::forward_as_tuple(config.bytes_per_second, config.burst_size)
                    );
                }
            }
        }
    }
}

// MARK: remove_throttle
void ThrottleManager::remove_throttle(DWORD pid) {
    std::lock_guard<std::mutex> lock(config_mutex);

    limiters.erase(pid);
    upload_limiters.erase(pid);
    download_limiters.erase(pid);
    configs.erase(pid);
}

void ThrottleManager::remove_throttle(const std::string& executable) {
    std::lock_guard<std::mutex> lock(config_mutex);

    exe_configs.erase(executable);

    // remove configs for all PIDs with this executable
    for (auto it = configs.begin(); it != configs.end();) {
        DWORD pid = it->first;
        auto& config_list = it->second;

        // remove configs that match this executable
        config_list.erase(
            std::remove_if(config_list.begin(), config_list.end(),
                [&executable](const ThrottleConfig& cfg) {
                    return cfg.executable == executable;
                }),
            config_list.end()
        );

        // if no configs left, remove the PID entry and its limiters
        if (config_list.empty()) {
            limiters.erase(pid);
            upload_limiters.erase(pid);
            download_limiters.erase(pid);
            it = configs.erase(it);
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
bool ThrottleManager::should_queue_packet(DWORD pid, uint32_t packet_size, PacketDirection direction) {
    std::lock_guard<std::mutex> lock(config_mutex);

    // check for PID specific configs
    auto config_it = configs.find(pid);
    std::vector<ThrottleConfig>* active_configs = nullptr;

    if (config_it != configs.end()) {
        active_configs = &config_it->second;
    } else {
        // check for executable specific configs
        std::string exe_name = pid_to_executable(pid);
        auto exe_it = exe_configs.find(exe_name);
        if (!exe_name.empty() && exe_it != exe_configs.end()) {
            // create configs for this PID
            configs[pid] = exe_it->second;
            active_configs = &configs[pid];

            // create limiters for each config
            for (const auto& cfg : *active_configs) {
                if (cfg.mode == 's') {
                    limiters.emplace(
                        std::piecewise_construct,
                        std::forward_as_tuple(pid),
                        std::forward_as_tuple(cfg.bytes_per_second, cfg.burst_size)
                    );
                } else if (cfg.mode == 'i') {
                    upload_limiters.emplace(
                        std::piecewise_construct,
                        std::forward_as_tuple(pid),
                        std::forward_as_tuple(cfg.bytes_per_second, cfg.burst_size)
                    );
                    download_limiters.emplace(
                        std::piecewise_construct,
                        std::forward_as_tuple(pid),
                        std::forward_as_tuple(cfg.bytes_per_second, cfg.burst_size)
                    );
                } else if (cfg.mode == 'u') {
                    upload_limiters.emplace(
                        std::piecewise_construct,
                        std::forward_as_tuple(pid),
                        std::forward_as_tuple(cfg.bytes_per_second, cfg.burst_size)
                    );
                } else if (cfg.mode == 'd') {
                    download_limiters.emplace(
                        std::piecewise_construct,
                        std::forward_as_tuple(pid),
                        std::forward_as_tuple(cfg.bytes_per_second, cfg.burst_size)
                    );
                }
            }
        } else if (each_mode) {
            // create default config for "each" mode
            ThrottleConfig default_config;
            default_config.pid = pid;
            default_config.bytes_per_second = each_rate ? each_rate : 1024 * 1024;
            default_config.burst_size = each_burst ? each_burst : default_config.bytes_per_second;
            default_config.mode = 's';
            configs[pid] = {default_config};
            active_configs = &configs[pid];

            limiters.emplace(
                std::piecewise_construct,
                std::forward_as_tuple(pid),
                std::forward_as_tuple(default_config.bytes_per_second, default_config.burst_size)
            );
        }
    }

    if (active_configs) {
        // check all applicable configs for this direction
        bool should_queue = false;

        for (const auto& cfg : *active_configs) {
            // skip configs that dont apply to this direction
            if (cfg.mode == 'u' && direction != PacketDirection::UPLOAD) continue;
            if (cfg.mode == 'd' && direction != PacketDirection::DOWNLOAD) continue;

            // check the appropriate limiter
            switch (cfg.mode) {
                case 'u': // upload only
                    {
                        auto it = upload_limiters.find(pid);
                        if (it != upload_limiters.end() && !it->second.try_consume(packet_size)) {
                            should_queue = true;
                        }
                    }
                    break;

                case 'd': // download only
                    {
                        auto it = download_limiters.find(pid);
                        if (it != download_limiters.end() && !it->second.try_consume(packet_size)) {
                            should_queue = true;
                        }
                    }
                    break;

                case 's': // shared limiter
                    {
                        auto it = limiters.find(pid);
                        if (it != limiters.end() && !it->second.try_consume(packet_size)) {
                            should_queue = true;
                        }
                    }
                    break;

                case 'i': // individual limiters
                    if (direction == PacketDirection::UPLOAD) {
                        auto it = upload_limiters.find(pid);
                        if (it != upload_limiters.end() && !it->second.try_consume(packet_size)) {
                            should_queue = true;
                        }
                    } else if (direction == PacketDirection::DOWNLOAD) {
                        auto it = download_limiters.find(pid);
                        if (it != download_limiters.end() && !it->second.try_consume(packet_size)) {
                            should_queue = true;
                        }
                    }
                    break;
            }
        }

        if (should_queue) return true;
    }

    // if no specific limiter, use global limiter if enabled
    if (global_mode && global_limiter) {
        return !global_limiter->try_consume(packet_size);
    }

    // no limiter, do not queue
    return false;
}

// MARK: queue_packet
void ThrottleManager::queue_packet(
    const char* packet,
    UINT packet_len,
    const WINDIVERT_ADDRESS& addr,
    DWORD pid,
    PacketDirection direction
) {
    QueuedPacket queued;
    queued.data.assign(packet, packet + packet_len);
    queued.addr = addr;
    queued.enqueue_time = std::chrono::steady_clock::now();
    queued.pid = pid;
    queued.direction = direction;

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
            auto config_it = configs.find(packet.pid);

            if (config_it == configs.end()) {
                // no longer throttled, send immediately
                can_send = true;
            } else {
                // check all applicable configs
                can_send = true;  // assume we can send unless a limiter blocks it
                std::chrono::milliseconds max_wait(0);

                for (const auto& config : config_it->second) {
                    // skip configs that dont apply to this direction
                    if (config.mode == 'u' && packet.direction != PacketDirection::UPLOAD) continue;
                    if (config.mode == 'd' && packet.direction != PacketDirection::DOWNLOAD) continue;

                    // try to consume tokens based on mode
                    bool this_can_send = false;
                    std::chrono::milliseconds this_wait(0);

                    switch (config.mode) {
                        case 'u': // upload only
                            {
                                auto it = upload_limiters.find(packet.pid);
                                if (it != upload_limiters.end()) {
                                    if (it->second.try_consume(packet.data.size())) {
                                        this_can_send = true;
                                    } else {
                                        this_wait = it->second.time_until_available(packet.data.size());
                                    }
                                }
                            }
                            break;

                        case 'd': // download only
                            {
                                auto it = download_limiters.find(packet.pid);
                                if (it != download_limiters.end()) {
                                    if (it->second.try_consume(packet.data.size())) {
                                        this_can_send = true;
                                    } else {
                                        this_wait = it->second.time_until_available(packet.data.size());
                                    }
                                }
                            }
                            break;

                        case 's': // shared limiter
                            {
                                auto it = limiters.find(packet.pid);
                                if (it != limiters.end()) {
                                    if (it->second.try_consume(packet.data.size())) {
                                        this_can_send = true;
                                    } else {
                                        this_wait = it->second.time_until_available(packet.data.size());
                                    }
                                }
                            }
                            break;

                        case 'i': // individual limiters
                            if (packet.direction == PacketDirection::UPLOAD) {
                                auto it = upload_limiters.find(packet.pid);
                                if (it != upload_limiters.end()) {
                                    if (it->second.try_consume(packet.data.size())) {
                                        this_can_send = true;
                                    } else {
                                        this_wait = it->second.time_until_available(packet.data.size());
                                    }
                                }
                            } else if (packet.direction == PacketDirection::DOWNLOAD) {
                                auto it = download_limiters.find(packet.pid);
                                if (it != download_limiters.end()) {
                                    if (it->second.try_consume(packet.data.size())) {
                                        this_can_send = true;
                                    } else {
                                        this_wait = it->second.time_until_available(packet.data.size());
                                    }
                                }
                            }
                            break;
                    }

                    if (!this_can_send) {
                        can_send = false;
                        max_wait = std::max(max_wait, this_wait);
                    }
                }

                wait_time = max_wait;
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