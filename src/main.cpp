#include <CLI11.hpp>
#include <iostream>
#include <thread>
#include <print>

#include "listener.h"
#include "throttle.h"
#include "config.h"


struct CLIOptions {
    bool verbose = false;
    bool quiet = false;
    std::vector<std::string> throttle_rules;
};


void parse_and_apply_throttle_rule(const std::string& rule) {
    size_t first_colon = rule.find(':');

    std::string target = rule.substr(0, first_colon);
    std::string remainder = rule.substr(first_colon + 1);

    size_t second_colon = remainder.find(':');
    std::string rate_str = (second_colon == std::string::npos) ? remainder : remainder.substr(0, second_colon);
    std::string burst_str = (second_colon == std::string::npos) ? "" : remainder.substr(second_colon + 1);

    auto parse_size = [](const std::string& s) -> uint64_t {
        if (s.empty()) return 0;

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
                    return 0;
            }
        }

        return static_cast<uint64_t>(value * multiplier);
    };

    uint64_t rate = parse_size(rate_str);
    uint64_t burst = burst_str.empty() ? rate : parse_size(burst_str);

    if (rate == 0) {
        std::fprintf(stderr, "Invalid rate in throttle rule: %s\n", rule.c_str());
        return;
    }

    ThrottleConfig config;
    config.bytes_per_second = rate;
    config.burst_size = burst;

    bool is_pid = true;
    for (char c : target) {
        if (!std::isdigit(c)) {
            is_pid = false;
            break;
        }
    }

    if (is_pid) {
        config.pid = std::stoul(target);
        std::fprintf(stdout, "Adding throttle for PID %lu: %llu bytes/s, burst %llu bytes\n",
            config.pid,
            static_cast<unsigned long long>(rate),
            static_cast<unsigned long long>(burst)
        );
    } else {
        if (target == "global" || target == "each") {
            config.executable = target;
            if (target == "each") {
                // Set default rate/burst for all processes
                config.bytes_per_second = rate;
                config.burst_size = burst;
            }
            std::fprintf(stdout, "Adding throttle for %s: %llu bytes/s, burst %llu bytes\n",
                target.c_str(),
                static_cast<unsigned long long>(rate),
                static_cast<unsigned long long>(burst)
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
            std::fprintf(stdout, "Adding throttle for %s: %llu bytes/s, burst %llu bytes\n",
                target.c_str(),
                static_cast<unsigned long long>(rate),
                static_cast<unsigned long long>(burst)
            );
        }
    }

    if (g_throttle_manager) {
        g_throttle_manager->add_throttle(config);
    }
}


int main(int argc, char** argv) {
    CLI::App app{"proclim - WinDivert-based per-process network bandwidth limiter for Windows"};

    CLIOptions options;

    app.add_flag("-v,--verbose", options.verbose, "Enable verbose output (shows all packets)");
    app.add_flag("-q,--quiet", options.quiet, "Suppress non-error output");

    app.add_option("-t,--throttle", options.throttle_rules,
        "Add throttle rule\n"
        "\n"
        "Format: target:rate[:burst]\n"
        "\n"
        "Target options:\n"
        "  <PID>       - Specific process ID\n"
        "  <exe>       - Executable name\n"
        "  system      - All processes\n"
        "  unknown     - Processes that couldn't be identified\n"
        "  global      - All network traffic (shared limiter)\n"
        "  each        - Each process gets individual limit\n"
        "\n"
        "Rate/Burst format:\n"
        "  Number with optional suffix: K (KiB/s), M (MiB/s), G (GiB/s)")
        ->expected(0, -1);

    app.get_option("--throttle")->check([](const std::string& rule) -> std::string {
        size_t first_colon = rule.find(':');
        if (first_colon == std::string::npos) {
            return "Invalid format. Expected 'target:rate[:burst]'";
        }

        std::string target = rule.substr(0, first_colon);
        if (target.empty()) {
            return "Target cannot be empty";
        }

        std::string remainder = rule.substr(first_colon + 1);
        if (remainder.empty()) {
            return "Rate cannot be empty";
        }

        return "";
    });

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        return app.exit(e);
    }

    if (options.verbose && options.quiet) {
        std::cerr << "Error: Cannot use both --verbose and --quiet" << std::endl;
        return 1;
    }

    g_config.verbose = options.verbose;
    g_config.quiet = options.quiet;


    std::thread flow_thread(flow_layer_listener);
    std::thread network_thread(network_layer_listener);
    std::thread queue_thread(packet_queue_processor);

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    if (!options.throttle_rules.empty()) {
        for (const auto& rule : options.throttle_rules) {
            parse_and_apply_throttle_rule(rule);
        }
    } else {
        if (!options.quiet) {
            std::println("No throttle rules specified. Monitoring traffic only.");
            std::println("Use --help for more information about parameters.");
        }
    }

    if (!options.quiet) {
        std::println("\nPress Ctrl+C to stop...");
    }

    flow_thread.join();
    network_thread.join();
    queue_thread.join();

    return 0;
}