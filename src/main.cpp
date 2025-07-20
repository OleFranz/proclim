#include <windivert.h>

#include <unordered_map>
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <thread>
#include <mutex>
#include <chrono>

#include "error.h"

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


void FlowLayerListener()
{
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

    WINDIVERT_ADDRESS addr;
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


void NetworkLayerListener()
{
    HANDLE network_handle = WinDivertOpen(
        "ip and tcp",
        WINDIVERT_LAYER_NETWORK,
        0,
        0
    );
    if (network_handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "WinDivertOpen(network) failed: %s\n", open_error_to_string(GetLastError()).c_str());
        return;
    }

    char packet[0xFFFF];
    UINT packet_len;
    WINDIVERT_ADDRESS addr;

    while (true) {
        if (!WinDivertRecv(network_handle, packet, sizeof(packet), &packet_len, &addr)) {
            fprintf(stderr, "WinDivertRecv(network) failed: %s\n", recv_error_to_string(GetLastError()).c_str());
            continue;
        }

        PWINDIVERT_IPHDR  iphdr;
        PWINDIVERT_TCPHDR tcphdr;
        WinDivertHelperParsePacket(
            packet, packet_len,
            &iphdr, nullptr, nullptr,
            nullptr, nullptr,
            &tcphdr, nullptr,
            nullptr, nullptr,
            nullptr, nullptr
        );
        if (!iphdr || !tcphdr) {
            // not IPv4/TCP
            WinDivertSend(network_handle, packet, packet_len, nullptr, &addr);
            continue;
        }

        FlowKey key;
        key.src_addr = WinDivertHelperNtohl(iphdr->SrcAddr);
        key.src_port = WinDivertHelperNtohs(tcphdr->SrcPort);
        key.dst_addr = WinDivertHelperNtohl(iphdr->DstAddr);
        key.dst_port = WinDivertHelperNtohs(tcphdr->DstPort);
        key.proto    = iphdr->Protocol;

        DWORD pid = -1;
        {
            std::lock_guard<std::mutex> lk(map_mutex);
            auto it = flow_to_pid.find(key);
            if (it != flow_to_pid.end())
                pid = it->second;
        }

        if (pid == 1) {
            // do something
        }

        WinDivertSend(network_handle, packet, packet_len, nullptr, &addr);
    }

    WinDivertClose(network_handle);
}

int main()
{
    std::thread sockThr(FlowLayerListener);
    std::thread netThr(NetworkLayerListener);

    puts("Running. Ctrl+C to quit.");
    sockThr.join();
    netThr.join();
    return 0;
}