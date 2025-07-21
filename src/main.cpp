#include <windivert.h>

#include <unordered_map>
#include <vector>
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
    uint8_t proto;

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


struct FragmentKey {
    uint32_t src;
    uint32_t dst;
    uint16_t id;
    uint8_t proto;

    bool operator==(FragmentKey const& o) const {
        return src == o.src && dst == o.dst
            && id == o.id && proto == o.proto;
    }
};

struct FragmentKeyHash {
    size_t operator()(FragmentKey const& k) const noexcept {
        return (size_t)k.proto
             ^ ((size_t)k.src << 1)
             ^ ((size_t)k.dst << 2)
             ^ ((size_t)k.id << 3);
    }
};


static std::unordered_map<FlowKey, DWORD, FlowKeyHash> flow_to_pid;
static std::mutex map_mutex;

static std::unordered_map<FragmentKey, std::vector<uint8_t>, FragmentKeyHash> frag_buf;
static std::unordered_map<FragmentKey, size_t, FragmentKeyHash> frag_len;
static std::mutex frag_mutex;


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

    while (true) {
        if (!WinDivertRecv(flow_handle, nullptr, 0, nullptr, &addr)) {
            fprintf(stderr, "WinDivertRecv(flow) failed: %s\n", recv_error_to_string(GetLastError()).c_str());
            continue;
        }

        FlowKey flow_key;
        flow_key.src_addr = addr.Flow.LocalAddr[0];
        flow_key.src_port = (uint16_t)addr.Flow.LocalPort;
        flow_key.dst_addr = addr.Flow.RemoteAddr[0];
        flow_key.dst_port = (uint16_t)addr.Flow.RemotePort;
        flow_key.proto = (uint8_t)addr.Flow.Protocol;

        std::lock_guard<std::mutex> lk(map_mutex);
        flow_to_pid[flow_key] = addr.Flow.ProcessId;
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

        PWINDIVERT_IPHDR iphdr = nullptr;
        PWINDIVERT_IPV6HDR ipv6hdr = nullptr;

        WinDivertHelperParsePacket(
            packet, packet_len,
            &iphdr, &ipv6hdr,
            nullptr, nullptr, nullptr,
            nullptr, nullptr,
            nullptr, nullptr,
            nullptr, nullptr
        );

        bool is_fragment = false;
        FragmentKey fragment_key{};
        UINT16 offset8 = 0;
        bool more_fragments = false;
        uint8_t* payload_ptr = nullptr;
        UINT payload_len = 0;

        if (iphdr) {
            UINT16 fragment_offset = WINDIVERT_IPHDR_GET_FRAGOFF(iphdr); // offset
            more_fragments = WINDIVERT_IPHDR_GET_MF(iphdr); // if true, more fragments expected
            is_fragment = (fragment_offset != 0) || more_fragments;
            if (is_fragment) {
                offset8 = fragment_offset;
                payload_ptr = (uint8_t*)iphdr + (iphdr->HdrLength * 4);
                payload_len = WinDivertHelperNtohs(iphdr->Length) - (iphdr->HdrLength * 4);
                fragment_key.src = WinDivertHelperNtohl(iphdr->SrcAddr);
                fragment_key.dst = WinDivertHelperNtohl(iphdr->DstAddr);
                fragment_key.id = WinDivertHelperNtohs(iphdr->Id);
                fragment_key.proto = iphdr->Protocol;
                std::lock_guard<std::mutex> lk(frag_mutex);
                auto &buf = frag_buf[fragment_key];
                auto &tot = frag_len[fragment_key];
                size_t needed = (offset8 * 8) + payload_len;
                if (buf.size() < needed) buf.resize(needed);
                memcpy(buf.data() + offset8 * 8, payload_ptr, payload_len);
                if (tot < needed) tot = needed;

                if (!more_fragments) {
                    UINT hdrLen = iphdr->HdrLength * 4;
                    UINT newLen = hdrLen + (UINT)tot;
                    std::vector<uint8_t> newPkt(newLen);
                    memcpy(newPkt.data(), packet, hdrLen);
                    auto* newIph = (PWINDIVERT_IPHDR)newPkt.data();
                    newIph->Length = WinDivertHelperHtons((UINT16)newLen);
                    WINDIVERT_IPHDR_SET_FRAGOFF(newIph, 0);
                    WINDIVERT_IPHDR_SET_MF(newIph, 0);
                    memcpy(newPkt.data() + hdrLen, buf.data(), tot);
                    PWINDIVERT_TCPHDR tcphdr = nullptr;
                    PWINDIVERT_UDPHDR udphdr = nullptr;
                    PWINDIVERT_ICMPHDR icmphdr = nullptr;
                    PWINDIVERT_ICMPV6HDR icmpv6hdr = nullptr;

                    WinDivertHelperParsePacket(
                        newPkt.data(),
                        newLen,
                        nullptr,
                        nullptr,
                        nullptr,
                        &icmphdr,
                        &icmpv6hdr,
                        &tcphdr,
                        &udphdr,
                        nullptr,
                        nullptr,
                        nullptr,
                        nullptr
                    );

                    FlowKey flow_key{};
                    flow_key.src_addr = fragment_key.src;
                    flow_key.dst_addr = fragment_key.dst;
                    flow_key.proto = fragment_key.proto;
                    if (tcphdr) {
                        flow_key.src_port = WinDivertHelperNtohs(tcphdr->SrcPort);
                        flow_key.dst_port = WinDivertHelperNtohs(tcphdr->DstPort);
                    } else if (udphdr) {
                        flow_key.src_port = WinDivertHelperNtohs(udphdr->SrcPort);
                        flow_key.dst_port = WinDivertHelperNtohs(udphdr->DstPort);
                    } else {
                        flow_key.src_port = 0;
                        flow_key.dst_port = 0;
                    }
                    DWORD pid = -1;
                    {
                        std::lock_guard<std::mutex> lk2(map_mutex);
                        auto it = flow_to_pid.find(flow_key);
                        if (it != flow_to_pid.end()) {
                            pid = it->second;
                        }
                    }


                    frag_buf.erase(fragment_key);
                    frag_len.erase(fragment_key);
                }
                continue;
            }
        }

        PWINDIVERT_TCPHDR tcphdr = nullptr;
        PWINDIVERT_UDPHDR udphdr = nullptr;
        PWINDIVERT_ICMPHDR icmphdr = nullptr;
        PWINDIVERT_ICMPV6HDR icmpv6hdr = nullptr;
        WinDivertHelperParsePacket(
            packet,
            packet_len,
            &iphdr,
            &ipv6hdr,
            nullptr,
            &icmphdr,
            &icmpv6hdr,
            &tcphdr,
            &udphdr,
            nullptr,
            nullptr,
            nullptr,
            nullptr
        );


        FlowKey flow_key;
        if (iphdr) {
            flow_key.src_addr = WinDivertHelperNtohl(iphdr->SrcAddr);
            flow_key.dst_addr = WinDivertHelperNtohl(iphdr->DstAddr);
            flow_key.proto = iphdr->Protocol;
        } else {
            flow_key.src_addr = WinDivertHelperNtohl(ipv6hdr->SrcAddr[3]);
            flow_key.dst_addr = WinDivertHelperNtohl(ipv6hdr->DstAddr[3]);
            flow_key.proto = ipv6hdr->NextHdr;
        }

        if (tcphdr) {
            flow_key.src_port = WinDivertHelperNtohs(tcphdr->SrcPort);
            flow_key.dst_port = WinDivertHelperNtohs(tcphdr->DstPort);
        } else if (udphdr) {
            flow_key.src_port = WinDivertHelperNtohs(udphdr->SrcPort);
            flow_key.dst_port = WinDivertHelperNtohs(udphdr->DstPort);
        } else {
            flow_key.src_port = 0;
            flow_key.dst_port = 0;
        }


        DWORD pid = -1;
        {
            std::lock_guard<std::mutex> lk(map_mutex);
            auto it = flow_to_pid.find(flow_key);
            if (it != flow_to_pid.end()) {
                pid = it->second;
            }
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

        const char* proto_str;
        switch (flow_key.proto) {
            case IPPROTO_TCP: proto_str = "TCP"; break;
            case IPPROTO_UDP: proto_str = "UDP"; break;
            case IPPROTO_ICMP: proto_str = "ICMP"; break;
            case IPPROTO_ICMPV6: proto_str = "ICMPV6"; break;
            default: proto_str = "UNKNOWN"; break;
        }

        printf(
            "[%s-%s] %s (%d) %u bytes\n",
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

int main() {
    std::thread sockThr(FlowLayerListener);
    std::thread netThr(NetworkLayerListener);

    sockThr.join();
    netThr.join();
    return 0;
}