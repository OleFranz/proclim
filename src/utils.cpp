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