#ifndef CONFIG_H
#define CONFIG_H

class Config {
public:
    static Config &instance()
    {
        static Config instance;
        return instance;
    }

    bool verbose = false;
    bool quiet = false;
    std::vector<std::string> exclude_targets;

private:
    Config() = default;
    Config(const Config &) = delete;
    Config &operator=(const Config &) = delete;
};

#define g_config Config::instance()

#endif