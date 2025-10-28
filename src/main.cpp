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
    if (first_colon == std::string::npos) {
        std::cerr << "Invalid throttle rule format: " << rule << std::endl;
        std::cerr << "Expected format: 'executable:rate[:burst]' or 'pid:rate[:burst]'" << std::endl;
        std::cerr << "  executable = executable name" << std::endl;
        std::cerr << "  pid        = process ID number" << std::endl;
        std::cerr << "  rate       = bandwidth limit (e.g., 1M for 1 MB/s)" << std::endl;
        std::cerr << "  burst      = burst size (optional, defaults to rate)" << std::endl;
        return;
    }

    std::string target = rule.substr(0, first_colon);
    std::string remainder = rule.substr(first_colon + 1);

    size_t second_colon = remainder.find(':');
    std::string rate_str = (second_colon == std::string::npos)
        ? remainder
        : remainder.substr(0, second_colon);
    std::string burst_str = (second_colon == std::string::npos)
        ? ""
        : remainder.substr(second_colon + 1);

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
                    std::cerr << "Unknown size unit: " << unit << std::endl;
                    return 0;
            }
        }

        return static_cast<uint64_t>(value * multiplier);
    };

    uint64_t rate = parse_size(rate_str);
    uint64_t burst = burst_str.empty() ? rate : parse_size(burst_str);

    if (rate == 0) {
        std::cerr << "Invalid rate in throttle rule: " << rule << std::endl;
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
        std::cout << "Adding throttle for PID " << config.pid
                  << ": " << rate << " bytes/s, burst " << burst << " bytes" << std::endl;
    } else {
        config.executable = target;
        std::cout << "Adding throttle for " << target
                  << ": " << rate << " bytes/s, burst " << burst << " bytes" << std::endl;
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
        "Add throttle rule for a specific process or PID\n"
        "Format: 'target:rate[:burst]'\n"
        "  target = executable name or PID\n"
        "  rate   = bandwidth limit in bytes/second (supports K/M/G suffixes)\n"
        "  burst  = maximum burst size in bytes (optional, defaults to rate)")
        ->expected(0, -1);

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