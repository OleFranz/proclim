#include <CLI11.hpp>
#include <iostream>
#include <thread>
#include <print>

#include "listener.h"
#include "config.h"


struct CLIOptions {
    bool verbose = false;
    bool quiet = false;
    std::vector<std::string> throttle_rules;
    std::vector<std::string> block_rules;
    std::vector<std::string> exclude_rules;
};


int main(int argc, char** argv) {
    CLI::App app{"netregu - WinDivert-based per-process network bandwidth limiter for Windows"};

    CLIOptions options;

    app.add_flag("-v,--verbose", options.verbose, "Enable verbose output (shows all packets)");
    app.add_flag("-q,--quiet", options.quiet, "Suppress non-error output");

    app.add_option("-t,--throttle", options.throttle_rules,
        "Add throttle rule\n"
        "\n"
        "Format: target:rate[:burst][:mode]\n"
        "\n"
        "Target options:\n"
        "  <PID>       - Specific process ID\n"
        "  <exe>       - Executable name\n"
        "  system      - All system processes\n"
        "  unknown     - Processes that couldn't be identified\n"
        "  global      - All network traffic (shared limiter)\n"
        "  each        - Each process gets individual limit\n"
        "\n"
        "Rate/Burst format:\n"
        "  Number with optional suffix: K (KiB/s), M (MiB/s), G (GiB/s)\n"
        "\n"
        "Throttle mode (optional, default shared limiter):\n"
        "  u           - Only limit upload\n"
        "  d           - Only limit download\n"
        "  s           - Shared limiter for both upload and download\n"
        "  i           - Individual limiters for upload and download\n")
        ->expected(0, -1);

    app.get_option("--throttle")->check([](const std::string& rule) -> std::string {
        if (rule.empty()) {
            return "Rule cannot be empty";
        }

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

    app.add_option("-b,--block", options.block_rules,
        "Block traffic\n"
        "\n"
        "Format: target[:mode]\n"
        "\n"
        "Target options:\n"
        "  <PID>       - Specific process ID\n"
        "  <exe>       - Executable name\n"
        "  system      - All system processes\n"
        "  unknown     - Processes that couldn't be identified\n"
        "  global      - All network traffic\n"
        "\n"
        "Throttle mode (optional, default shared limiter):\n"
        "  u           - Only block upload\n"
        "  d           - Only block download\n"
        "  b           - Block both upload and download\n")
        ->expected(0, -1);

    app.get_option("--block")->check([](const std::string& rule) -> std::string {
        if (rule.empty()) {
            return "Rule cannot be empty";
        }

        size_t first_colon = rule.find(':');
        std::string target;

        if (first_colon == std::string::npos) {
            target = rule;
        } else {
            target = rule.substr(0, first_colon);
            if (target.empty()) {
                return "Target cannot be empty";
            }
        }

        return "";
    });

    app.add_option("-e,--exclude", options.exclude_rules,
        "Exclude from all rules\n"
        "\n"
        "Format: target\n"
        "\n"
        "Target options:\n"
        "  <PID>       - Specific process ID\n"
        "  <exe>       - Executable name\n")
        ->expected(0, -1);

    app.get_option("--exclude")->check([](const std::string& rule) -> std::string {
        if (rule.empty()) {
            return "Rule cannot be empty";
        }
        printf("Ignoring all rules for target: %s\n", rule.c_str());

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
    g_config.exclude_targets = options.exclude_rules;


    std::thread flow_thread(flow_layer_listener);
    std::thread network_thread(network_layer_listener);
    std::thread queue_thread(packet_queue_processor);

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    if (!options.throttle_rules.empty() || !options.block_rules.empty()) {
        for (const auto& rule : options.throttle_rules) {
            parse_and_apply_throttle_rule(rule);
        }
        for (const auto& rule : options.block_rules) {
            parse_and_apply_block_rule(rule);
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