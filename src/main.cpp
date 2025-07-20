#include <windivert.h>

#include <unordered_map>
#include <windows.h>
#include <cstdint>
#include <psapi.h>
#include <cstdio>
#include <thread>
#include <mutex>
#include <chrono>

#include "error.h"

#define MAX_PACKET_SIZE 0xFFFF

// windivert.h does not include this for some reason...
#define IPPROTO_ICMPV6 58


struct FlowKey {
    uint32_t src_addr;
    uint16_t src_port;
    uint32_t dst_addr;
    uint16_t dst_port;
    uint8_t  proto;

    bool operator==(FlowKey const& o) const {
        return src_addr==o.src_addr
            && src_port==o.src_port
            && dst_addr==o.dst_addr
            && dst_port==o.dst_port
            && proto==o.proto;
    }
};

struct FlowKeyHash {
    size_t operator()(FlowKey const& k) const noexcept {
        return (size_t)k.proto
             ^ ((size_t)k.src_addr << 1)
             ^ ((size_t)k.dst_addr << 2)
             ^ ((size_t)k.src_port << 3)
             ^ ((size_t)k.dst_port << 4);
    }
};


static std::unordered_map<FlowKey, DWORD, FlowKeyHash> flow_to_pid;
static std::mutex map_mutex;


void FlowLayerListener() {
    WINDIVERT_ADDRESS addr;

    HANDLE flow_handle = WinDivertOpen(
        "true", // capture all
        WINDIVERT_LAYER_FLOW,
        0,
        WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY // required for FLOW layer
    );
    if (flow_handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "WinDivertOpen(flow) failed: %s\n", open_error_to_string(GetLastError()).c_str());
        return;
    }

    while (true)
    {
        if (!WinDivertRecv(flow_handle, nullptr, 0, nullptr, &addr)) {
            fprintf(stderr, "WinDivertRecv(flow) failed: %s\n", recv_error_to_string(GetLastError()).c_str());
            continue;
        }

        FlowKey key;
        key.src_addr = addr.Flow.LocalAddr[0];
        key.src_port = (uint16_t)addr.Flow.LocalPort;
        key.dst_addr = addr.Flow.RemoteAddr[0];
        key.dst_port = (uint16_t)addr.Flow.RemotePort;
        key.proto    = (uint8_t)addr.Flow.Protocol;

        std::lock_guard<std::mutex> lk(map_mutex);
        if (true) {
            flow_to_pid[key] = addr.Flow.ProcessId;
        }
        else {
            flow_to_pid.erase(key);
        }
    }

    WinDivertClose(flow_handle);
}


void NetworkLayerListener() {
    char packet[MAX_PACKET_SIZE];
    UINT packet_len;
    WINDIVERT_ADDRESS addr;

    HANDLE network_handle = WinDivertOpen(
        "ip or ipv6",
        WINDIVERT_LAYER_NETWORK,
        0,
        0
    );
    if (network_handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "WinDivertOpen(network) failed: %s\n", open_error_to_string(GetLastError()).c_str());
        return;
    }

    while (true) {
        if (!WinDivertRecv(network_handle, packet, sizeof(packet), &packet_len, &addr)) {
            fprintf(stderr, "WinDivertRecv(network) failed: %s\n", recv_error_to_string(GetLastError()).c_str());
            continue;
        }

        PWINDIVERT_IPHDR   iphdr = nullptr;
        PWINDIVERT_IPV6HDR ipv6hdr = nullptr;
        PWINDIVERT_TCPHDR  tcphdr = nullptr;
        PWINDIVERT_UDPHDR  udphdr = nullptr;

        WinDivertHelperParsePacket(
            packet,
            packet_len,
            &iphdr,
            &ipv6hdr,
            nullptr,
            nullptr,
            nullptr,
            &tcphdr,
            &udphdr,
            nullptr,
            nullptr,
            nullptr,
            nullptr
        );

        if (!iphdr && !ipv6hdr) {
            // not IPv4/IPv6
            if (!WinDivertSend(network_handle, packet, packet_len, nullptr, &addr)) {
                fprintf(stderr, "WinDivertSend(network) failed: %s\n", send_error_to_string(GetLastError()).c_str());
            }
            continue;
        }

        FlowKey key;
        if (iphdr) {
            key.src_addr = WinDivertHelperNtohl(iphdr->SrcAddr);
            key.dst_addr = WinDivertHelperNtohl(iphdr->DstAddr);
            key.proto = iphdr->Protocol;
        } else {
            key.src_addr = WinDivertHelperNtohl(ipv6hdr->SrcAddr[3]);
            key.dst_addr = WinDivertHelperNtohl(ipv6hdr->DstAddr[3]);
            key.proto = ipv6hdr->NextHdr;
        }

        // Get ports if TCP/UDP, otherwise use 0
        if (tcphdr) {
            key.src_port = WinDivertHelperNtohs(tcphdr->SrcPort);
            key.dst_port = WinDivertHelperNtohs(tcphdr->DstPort);
        } else if (udphdr) {
            key.src_port = WinDivertHelperNtohs(udphdr->SrcPort);
            key.dst_port = WinDivertHelperNtohs(udphdr->DstPort);
        } else {
            key.src_port = 0;
            key.dst_port = 0;
        }

        const char* proto_str;
        switch(key.proto) {
            case IPPROTO_TCP: proto_str = "TCP"; break;
            case IPPROTO_UDP: proto_str = "UDP"; break;
            case IPPROTO_ICMP: proto_str = "ICMP"; break;
            case IPPROTO_ICMPV6: proto_str = "ICMPV6"; break;
            default: proto_str = "UNKNOWN"; break;
        }

        DWORD pid = -1;
        {
            std::lock_guard<std::mutex> lk(map_mutex);
            auto it = flow_to_pid.find(key);
            if (it != flow_to_pid.end())
                pid = it->second;
        }


        const char* ip_ver = iphdr ? "IPv4" : "IPv6";
        const char* executable = "Unknown";

        if (pid == 4) {
            executable = "Windows";
        } else if (pid != -1) {
            HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (process) {
                char name[MAX_PATH];
                DWORD size = MAX_PATH;
                if (QueryFullProcessImageName(process, 0, name, &size)) {
                    executable = strrchr(name, '\\') + 1; // only keep file name
                }
                CloseHandle(process);
            }
        }

        printf(
            "[%s-%s] %s (%d) %d bytes\n",
            ip_ver,
            proto_str,
            executable,
            pid,
            packet_len
        );


        if (!WinDivertSend(network_handle, packet, packet_len, nullptr, &addr)) {
            fprintf(stderr, "WinDivertSend(network) failed: %s\n", send_error_to_string(GetLastError()).c_str());
        }
    }

    WinDivertClose(network_handle);
}

int main()
{
    std::thread sockThr(FlowLayerListener);
    std::thread netThr(NetworkLayerListener);

    sockThr.join();
    netThr.join();
    return 0;
}