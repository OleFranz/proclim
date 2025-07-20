#include "error.h"

using namespace std;

// see: https://reqrypt.org/windivert-doc.html#divert_open
string open_error_to_string(int code) {
    switch (code) {
        case 2:
            return format("ERROR_FILE_NOT_FOUND (CODE: {}): The driver files WinDivert32.sys or WinDivert64.sys were not found.", code);
        case 5:
            return format("ERROR_ACCESS_DENIED (CODE: {}): The calling application does not have Administrator privileges.", code);
        case 87:
           return format("ERROR_INVALID_PARAMETER (CODE: {}): This indicates an invalid packet filter string, layer, priority, or flags.", code);
        case 577:
           return format("ERROR_INVALID_IMAGE_HASH (CODE: {}): The WinDivert32.sys or WinDivert64.sys driver does not have a valid digital signature.", code);
        case 654:
            return format("ERROR_DRIVER_FAILED_PRIOR_UNLOAD (CODE: {}): An incompatible version of the WinDivert driver is currently loaded.", code);
        case 1060:
            return format("ERROR_SERVICE_DOES_NOT_EXIST (CODE: {}): The handle was opened with the WINDIVERT_FLAG_NO_INSTALL flag and the WinDivert driver is not already installed.", code);
        case 1275:
            return format("ERROR_DRIVER_BLOCKED (CODE: {}): This error occurs for various reasons, including: 1. the WinDivert driver is blocked by security software; or 2. you are using a virtualization environment that does not support drivers.", code);
        case 1753:
            return format("EPT_S_NOT_REGISTERED (CODE: {}): This error occurs when the Base Filtering Engine service has been disabled.", code);
    }
    // fallback
    return format("UNKNOWN_ERROR (CODE: {})", code);
}

// see: https://reqrypt.org/windivert-doc.html#divert_send
string send_error_to_string(int code) {
    switch (code) {
        case 1232:
            return format("ERROR_HOST_UNREACHABLE (CODE: {}): This error occurs when an impostor packet (with pAddr->Impostor set to 1) is injected and the ip.TTL or ipv6.HopLimit field goes to zero. This is a defense of last resort against infinite loops caused by impostor packets.", code);
    }
    // fallback
    return format("UNKNOWN_ERROR (CODE: {})", code);
}

// see: https://reqrypt.org/windivert-doc.html#divert_recv
string recv_error_to_string(int code) {
    switch (code) {
        case 122:
            return format("ERROR_INSUFFICIENT_BUFFER: The captured packet is larger than the pPacket buffer.", code);
        case 232:
            return format("ERROR_NO_DATA: The handle has been shutdown using WinDivertShutdown() and the packet queue is empty.", code);
    }
    // fallback
    return format("UNKNOWN_ERROR (CODE: {})", code);
}