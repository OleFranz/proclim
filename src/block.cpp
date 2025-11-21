#include "block.h"


// MARK: BlockManager
static bool global_mode = false;
static BlockConfig global_block_config;

BlockManager::BlockManager(HANDLE handle)
    : network_handle(handle)
    , running(true) {
}

// MARK: add_block
void BlockManager::add_block(const BlockConfig& config) {
    std::lock_guard<std::mutex> lock(config_mutex);

    if (config.executable == "global") {
        global_mode = true;
        global_block_config = config;
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
            }
        }
    }
}

// MARK: remove_block
void BlockManager::remove_block(DWORD pid) {
    std::lock_guard<std::mutex> lock(config_mutex);

    configs.erase(pid);
}

void BlockManager::remove_block(const std::string& executable) {
    std::lock_guard<std::mutex> lock(config_mutex);

    exe_configs.erase(executable);

    // remove configs for all PIDs with this executable
    for (auto it = configs.begin(); it != configs.end();) {
        DWORD pid = it->first;
        auto& config_list = it->second;

        // remove configs that match this executable
        config_list.erase(
            std::remove_if(config_list.begin(), config_list.end(),
                [&executable](const BlockConfig& cfg) {
                    return cfg.executable == executable;
                }),
            config_list.end()
        );

        // if no configs left, remove the PID entry and its limiters
        if (config_list.empty()) {
            it = configs.erase(it);
        } else {
            ++it;
        }
    }
}

void BlockManager::remove_block(DWORD pid, const std::string& executable) {
    remove_block(pid);
    remove_block(executable);
}

// MARK: should_block_packet
bool BlockManager::should_block_packet(DWORD pid, uint32_t packet_size, PacketDirection direction) {
    std::lock_guard<std::mutex> lock(config_mutex);

    // check for PID specific configs
    auto config_it = configs.find(pid);
    std::vector<BlockConfig>* active_configs = nullptr;
    bool has_specific_config = false;  // track if we found a specific config

    if (config_it != configs.end()) {
        active_configs = &config_it->second;
        has_specific_config = true;
    } else {
        // check for executable specific configs
        std::string exe_name = pid_to_executable(pid);
        for (const auto& ex : g_config.exclude_targets) {
            if (ex == std::to_string(pid) || ex == exe_name) {
                return false;
            }
        }

        auto exe_it = exe_configs.find(exe_name);
        if (!exe_name.empty() && exe_it != exe_configs.end()) {
            // create configs for this PID
            configs[pid] = exe_it->second;
            active_configs = &configs[pid];
            has_specific_config = true;
        }
    }

    if (active_configs) {
        // check all applicable configs for this direction
        bool should_block = false;

        for (const auto& cfg : *active_configs) {
            // skip configs that dont apply to this direction
            if (cfg.mode == 'u' && direction != PacketDirection::UPLOAD) continue;
            if (cfg.mode == 'd' && direction != PacketDirection::DOWNLOAD) continue;
            should_block = true;
        }

        if (should_block) return true;
    }

    // block if in global mode and no specific config found
    if (!has_specific_config && global_mode) {
        switch (global_block_config.mode) {
            case 'u': // upload only
                return direction == PacketDirection::UPLOAD;
            case 'd': // download only
                return direction == PacketDirection::DOWNLOAD;
            case 'b': // block both
                return true;
            default:
                return false;
        }
    }

    // do not block
    return false;
}


// MARK: stop
void BlockManager::stop() {
    running = false;
}


// MARK: Block functions
BlockManager* g_block_manager = nullptr;

void init_block_system(HANDLE network_handle) {
    if (g_block_manager) {
        delete g_block_manager;
    }

    g_block_manager = new BlockManager(network_handle);
}

void shutdown_block_system() {
    if (g_block_manager) {
        g_block_manager->stop();
        delete g_block_manager;
        g_block_manager = nullptr;
    }
}