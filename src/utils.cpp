#include "utils.h"

#define INET_ADDRSTRLEN 16
#define INET6_ADDRSTRLEN 46

using namespace std;


const char* pid_to_executable(const DWORD pid) {
    static char executable[MAX_PATH] = "unknown";

    if (pid == 4) {
        strcpy_s(executable, MAX_PATH, "system");
    } else if (pid != -1) {
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (process) {
            char name[MAX_PATH];
            DWORD size = MAX_PATH;
            if (QueryFullProcessImageName(process, 0, name, &size)) {
                const char* filename = strrchr(name, '\\');
                if (filename) {
                    strcpy_s(executable, MAX_PATH, filename + 1);
                } else {
                    strcpy_s(executable, MAX_PATH, name);
                }
            } else {
                strcpy_s(executable, MAX_PATH, "unknown");
            }
            CloseHandle(process);
        } else {
            strcpy_s(executable, MAX_PATH, "unknown");
        }
    } else {
        strcpy_s(executable, MAX_PATH, "unknown");
    }

    return executable;
}


const char* ip_to_string(UINT32 address, bool is_ipv4) {
    if (is_ipv4) {
        return ipv4_to_string(address);
    }
    return ipv6_to_string(address);
}


const char* ipv4_to_string(UINT32 address) {
    static char address_string[INET_ADDRSTRLEN];
    WinDivertHelperFormatIPv4Address(
        address,
        address_string,
        sizeof(address_string)
    );
    return address_string;
}


const char* ipv6_to_string(UINT32 address) {
    static char address_string[INET6_ADDRSTRLEN];
    WinDivertHelperFormatIPv6Address(
        &address,
        address_string,
        sizeof(address_string)
    );
    return address_string;
}


void parse_and_apply_throttle_rule(const std::string& rule) {
    size_t first_colon = rule.find(':');

    std::string target = rule.substr(0, first_colon);
    std::string remainder = rule.substr(first_colon + 1);

    size_t second_colon = remainder.find(':');
    std::string rate_str = (second_colon == std::string::npos) ? remainder : remainder.substr(0, second_colon);
    std::string optional_param_str = (second_colon == std::string::npos) ? "" : remainder.substr(second_colon + 1);

    auto parse_size = [](const std::string& s) -> uint64_t {
        if (s.empty()) return -1;

        char* end;
        double value = std::strtod(s.c_str(), &end);

        uint64_t multiplier = 1;
        if (*end != '\0') {
            char unit = std::toupper(*end);
            switch (unit) {
                case 'K': multiplier = 1024; break;
                case 'M': multiplier = 1024 * 1024; break;
                case 'G': multiplier = 1024 * 1024 * 1024; break;
                default:
                    std::fprintf(stderr, "Unknown size unit: %c\n", unit);
                    return -1;
            }
        }

        return static_cast<uint64_t>(value * multiplier);
    };

    uint64_t rate = parse_size(rate_str);
    uint64_t burst = rate;  // default burst size = rate
    char throttle_mode = 's';  // default shared limiter

    // check if optional_param_str indicates the throttle mode or burst size
    if (!optional_param_str.empty()) {
        switch (std::tolower(optional_param_str[0])) {
            case 'u':
            case 'd':
            case 's':
            case 'i':
                throttle_mode = std::tolower(optional_param_str[0]);
                break;
            default: {
                size_t first_colon = optional_param_str.find(':');
                std::string burst_str = (first_colon == std::string::npos) ? optional_param_str : optional_param_str.substr(0, first_colon);
                std::string throttle_mode_str = (first_colon == std::string::npos) ? "" : optional_param_str.substr(first_colon + 1);
                if (!burst_str.empty()) {
                    burst = parse_size(burst_str);
                }
                if (!throttle_mode_str.empty()) {
                    throttle_mode = std::tolower(throttle_mode_str[0]);
                }
                break;
            }
        }
    }

    // negative uint is just a very large number
    if (rate == (uint64_t)-1) {
        std::fprintf(stderr, "Invalid rate in throttle rule: %s\n", rule.c_str());
        return;
    }
    if (burst == (uint64_t)-1) {
        std::fprintf(stderr, "Invalid burst size in throttle rule: %s\n", rule.c_str());
        return;
    }
    if (throttle_mode != 'u' && throttle_mode != 'd' && throttle_mode != 's' && throttle_mode != 'i') {
        std::fprintf(stderr, "Invalid mode in throttle rule: %s\n", rule.c_str());
        return;
    }

    ThrottleConfig config;
    config.bytes_per_second = rate;
    config.burst_size = burst;
    config.mode = throttle_mode;

    bool is_pid = true;
    for (char c : target) {
        if (!std::isdigit(c)) {
            is_pid = false;
            break;
        }
    }

    if (is_pid) {
        config.pid = std::stoul(target);
        std::fprintf(stdout, "Adding throttle for PID %lu: %llu bytes/s, burst %llu bytes, %s\n",
            config.pid,
            static_cast<unsigned long long>(rate),
            static_cast<unsigned long long>(burst),
            (throttle_mode == 'u') ? "upload only" :
            (throttle_mode == 'd') ? "download only" :
            (throttle_mode == 'i') ? "individual upload/download" : "shared upload/download"
        );
    } else {
        if (target == "global" || target == "each") {
            config.executable = target;
            if (target == "each") {
                // set default rate/burst for all processes
                config.bytes_per_second = rate;
                config.burst_size = burst;
            }
            std::fprintf(stdout, "Adding throttle for %s: %llu bytes/s, burst %llu bytes, %s\n",
                target.c_str(),
                static_cast<unsigned long long>(rate),
                static_cast<unsigned long long>(burst),
                (throttle_mode == 'u') ? "upload only" :
                (throttle_mode == 'd') ? "download only" :
                (throttle_mode == 'i') ? "individual upload/download" : "shared upload/download"
            );
        } else {
            if (target.size() < 4 || target.substr(target.size() - 4) != ".exe") {
                switch (tolower(target[0])) {
                    case 's':
                    target = "system";  // limit system processes
                    break;

                    case 'u':
                    target = "unknown";  // limit unknown processes
                    break;

                    case 'g':
                    target = "global";  // all processes on one limiter
                    break;

                    case 'e':
                    target = "each";  // limit all processes individually
                    break;

                    default:
                    std::fprintf(stderr, "Unknown target: %s\n", target.c_str());
                    return;
                }
            }

            config.executable = target;
            std::fprintf(stdout, "Adding throttle for %s: %llu bytes/s, burst %llu bytes, %s\n",
                target.c_str(),
                static_cast<unsigned long long>(rate),
                static_cast<unsigned long long>(burst),
                (throttle_mode == 'u') ? "upload only" :
                (throttle_mode == 'd') ? "download only" :
                (throttle_mode == 'i') ? "individual upload/download" : "shared upload/download"
            );
        }
    }

    if (g_throttle_manager) {
        g_throttle_manager->add_throttle(config);
    }
}


void parse_and_apply_block_rule(const std::string& rule) {
    size_t first_colon = rule.find(':');

    std::string target;
    char mode;

    if (first_colon == std::string::npos) {
        target = rule;
        mode = 'b';  // default block both upload and download
    } else {
        target = rule.substr(0, first_colon);
        mode = rule[first_colon + 1];
        switch (std::tolower(mode)) {
            case 'u':
            case 'd':
            case 'b':
                mode = std::tolower(mode);
                break;
        }
    }

    if (mode != 'u' && mode != 'd' && mode != 'b') {
        std::fprintf(stderr, "Invalid mode in block rule: %s\n", rule.c_str());
        return;
    }

    BlockConfig config;
    config.mode = mode;

    bool is_pid = true;
    for (char c : target) {
        if (!std::isdigit(c)) {
            is_pid = false;
            break;
        }
    }

    if (is_pid) {
        config.pid = std::stoul(target);
        std::fprintf(stdout, "Adding block for PID %lu %s\n",
            config.pid,
            (mode == 'u') ? "(upload only)" :
            (mode == 'd') ? "(download only)" : "(upload and download)"
        );
    } else {
        if (target == "global") {
            config.executable = target;
            std::fprintf(stdout, "Adding block for %s %s\n",
                target.c_str(),
                (mode == 'u') ? "(upload only)" :
                (mode == 'd') ? "(download only)" : "(upload and download)"
            );
        } else {
            if (target.size() < 4 || target.substr(target.size() - 4) != ".exe") {
                switch (tolower(target[0])) {
                    case 's':
                    target = "system";  // block system processes
                    break;

                    case 'u':
                    target = "unknown";  // block unknown processes
                    break;

                    case 'g':
                    target = "global";  // block all processes
                    break;

                    default:
                    std::fprintf(stderr, "Unknown target: %s\n", target.c_str());
                    return;
                }
            }

            config.executable = target;
            std::fprintf(stdout, "Adding block for %s %s\n",
                target.c_str(),
                (mode == 'u') ? "(upload only)" :
                (mode == 'd') ? "(download only)" : "(upload and download)"
            );
        }
    }

    if (g_block_manager) {
        g_block_manager->add_block(config);
    }
}