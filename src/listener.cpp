#include "listener.h"

#define MAX_PACKET_SIZE 0xFFFF


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

struct FlowInfo {
    DWORD pid;
    std::chrono::steady_clock::time_point last_seen;
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


static std::unordered_map<FlowKey, FlowInfo, FlowKeyHash> flow_to_pid;
static std::mutex map_mutex;

static std::unordered_map<FragmentKey, std::vector<uint8_t>, FragmentKeyHash> frag_buf;
static std::unordered_map<FragmentKey, size_t, FragmentKeyHash> frag_len;
static std::mutex frag_mutex;


void register_existing_connections() {
    {
        DWORD bufLen = 0;
        if (GetExtendedTcpTable(nullptr, &bufLen, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER)
            throw std::system_error(GetLastError(), std::system_category(), "GetExtendedTcpTable sizing");

        std::vector<BYTE> buffer(bufLen);
        auto tcpTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());

        if (auto err = GetExtendedTcpTable(tcpTable, &bufLen, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0); err != NO_ERROR)
            throw std::system_error(err, std::system_category(), "GetExtendedTcpTable");

        for (DWORD i = 0; i < tcpTable->dwNumEntries; ++i) {
            const auto& row = tcpTable->table[i];
            if (g_config.verbose) {
                printf("tcp connection: %-3i: [%-15s:%-5u - %-15s:%-5u] %-30s (%-5d)\n",
                    i,
                    ipv4_to_string(WinDivertHelperHtonl((UINT32)row.dwLocalAddr)),
                    WinDivertHelperNtohs(USHORT(row.dwLocalPort)),
                    ipv4_to_string(WinDivertHelperHtonl((UINT32)row.dwRemoteAddr)),
                    WinDivertHelperNtohs(USHORT(row.dwRemotePort)),
                    pid_to_executable(row.dwOwningPid),
                    row.dwOwningPid
                );
            }
            FlowKey flow_key;
            flow_key.src_addr = WinDivertHelperNtohl((UINT32)row.dwLocalAddr);
            flow_key.src_port = WinDivertHelperNtohs(USHORT(row.dwLocalPort));
            flow_key.dst_addr = WinDivertHelperNtohl((UINT32)row.dwRemoteAddr);
            flow_key.dst_port = WinDivertHelperNtohs(USHORT(row.dwRemotePort));
            flow_key.proto = IPPROTO_TCP;
            {
                std::lock_guard<std::mutex> lk(map_mutex);
                flow_to_pid[flow_key] = {(UINT32)row.dwOwningPid, std::chrono::steady_clock::now()};
            }
        }
    }

    {
        DWORD bufLen = 0;
        if (GetExtendedUdpTable(nullptr, &bufLen, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) != ERROR_INSUFFICIENT_BUFFER)
            throw std::system_error(GetLastError(), std::system_category(), "GetExtendedUdpTable sizing");

        std::vector<BYTE> buffer(bufLen);
        auto udpTable = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(buffer.data());

        if (auto err = GetExtendedUdpTable(udpTable, &bufLen, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0); err != NO_ERROR)
            throw std::system_error(err, std::system_category(), "GetExtendedUdpTable");

        for (DWORD i = 0; i < udpTable->dwNumEntries; ++i) {
            const auto& row = udpTable->table[i];
            if (g_config.verbose) {
                printf("udp connection: %-3i: [%-15s:%-5u - %-15s:%-5u] %-30s (%-5d)\n",
                    i,
                    ipv4_to_string(WinDivertHelperHtonl((UINT32)row.dwLocalAddr)),
                    WinDivertHelperNtohs(USHORT(row.dwLocalPort)),
                    ipv4_to_string(WinDivertHelperHtonl((UINT32)0)),
                    WinDivertHelperNtohs(USHORT(0)),
                    pid_to_executable(row.dwOwningPid),
                    row.dwOwningPid
                );
            }
            FlowKey flow_key;
            flow_key.src_addr = WinDivertHelperNtohl((UINT32)row.dwLocalAddr);
            flow_key.src_port = WinDivertHelperNtohs(USHORT(row.dwLocalPort));
            flow_key.dst_addr = 0;
            flow_key.dst_port = 0;
            flow_key.proto = IPPROTO_UDP;
            {
                std::lock_guard<std::mutex> lock(map_mutex);
                flow_to_pid[flow_key] = {(UINT32)row.dwOwningPid, std::chrono::steady_clock::now()};
            }
        }
    }
}


void flow_layer_listener() {
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

    register_existing_connections();

    while (true) {
        if (!WinDivertRecv(flow_handle, nullptr, 0, nullptr, &addr)) {
            fprintf(stderr, "WinDivertRecv(flow) failed: %s\n", recv_error_to_string(GetLastError()).c_str());
            continue;
        }

        FlowKey flow_key;
        switch (addr.Event) {
            case WINDIVERT_EVENT_FLOW_ESTABLISHED:
                flow_key.src_addr = addr.Flow.LocalAddr[0];
                flow_key.src_port = (USHORT)addr.Flow.LocalPort;
                flow_key.dst_addr = addr.Flow.RemoteAddr[0];
                flow_key.dst_port = (USHORT)addr.Flow.RemotePort;
                flow_key.proto = (uint8_t)addr.Flow.Protocol;
                {
                    std::lock_guard<std::mutex> lk(map_mutex);
                    flow_to_pid[flow_key] = {addr.Flow.ProcessId, std::chrono::steady_clock::now()};
                }
                break;
            case WINDIVERT_EVENT_FLOW_DELETED:
                flow_key.src_addr = addr.Flow.LocalAddr[0];
                flow_key.src_port = (USHORT)addr.Flow.LocalPort;
                flow_key.dst_addr = addr.Flow.RemoteAddr[0];
                flow_key.dst_port = (USHORT)addr.Flow.RemotePort;
                flow_key.proto = (uint8_t)addr.Flow.Protocol;
                {
                    std::lock_guard<std::mutex> lk(map_mutex);
                    auto it = flow_to_pid.find(flow_key);
                    if (it != flow_to_pid.end()) {
                        flow_to_pid.erase(flow_key);
                    }
                }
                break;
        }
    }

    WinDivertClose(flow_handle);
}


void network_layer_listener() {
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


    // initialize throttle system
    init_throttle_system(network_handle);


    while (true) {
        if (!WinDivertRecv(network_handle, packet, sizeof(packet), &packet_len, &addr)) {
            fprintf(stderr, "WinDivertRecv(network) failed: %s\n", recv_error_to_string(GetLastError()).c_str());
            continue;
        }

        PWINDIVERT_IPHDR iphdr = nullptr;
        PWINDIVERT_IPV6HDR ipv6hdr = nullptr;
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
                pid = it->second.pid;
                flow_to_pid[flow_key].last_seen = std::chrono::steady_clock::now();
            } else {
                FlowKey reverse_key = flow_key;
                reverse_key.src_addr = flow_key.dst_addr;
                reverse_key.dst_addr = flow_key.src_addr;
                reverse_key.src_port = flow_key.dst_port;
                reverse_key.dst_port = flow_key.src_port;

                auto reverse_it = flow_to_pid.find(reverse_key);
                if (reverse_it != flow_to_pid.end()) {
                    pid = reverse_it->second.pid;
                    flow_to_pid[reverse_key].last_seen = std::chrono::steady_clock::now();
                }
            }
        }


        const char* ip_ver = iphdr ? "IPv4" : "IPv6";

        const char* proto_str;
        switch (flow_key.proto) {
            case IPPROTO_TCP: proto_str = "TCP"; break;
            case IPPROTO_UDP: proto_str = "UDP"; break;
            case IPPROTO_ICMP: proto_str = "ICMP"; break;
            case IPPROTO_ICMPV6: proto_str = "ICMPV6"; break;
            default: proto_str = "UNKNOWN"; break;
        }

        auto executable = pid_to_executable(pid);

        bool should_queue = false;
        if (g_throttle_manager && pid != (DWORD)-1) {
            should_queue = g_throttle_manager->should_queue_packet(pid, packet_len);
        }

        if (should_queue) {
            // queue packet for delayed sending
            g_throttle_manager->queue_packet(packet, packet_len, addr, pid);

            if (g_config.verbose) {
                printf(
                    "(%-3zu) [%-15s:%-5u - %-15s:%-5u] [%-2s-%-3s] %-30s (%-5d) %-4u bytes [Q]\n",
                    flow_to_pid.size(),
                    ipv4_to_string((UINT32)flow_key.src_addr),
                    flow_key.src_port,
                    ipv4_to_string((UINT32)flow_key.dst_addr),
                    flow_key.dst_port,
                    ip_ver,
                    proto_str,
                    executable,
                    pid,
                    packet_len
                );
            }
        } else {
            // send immediately
            if (g_config.verbose) {
                printf(
                    "(%-3zu) [%-15s:%-5u - %-15s:%-5u] [%-2s-%-3s] %-30s (%-5d) %-4u bytes\n",
                    flow_to_pid.size(),
                    ipv4_to_string((UINT32)flow_key.src_addr),
                    flow_key.src_port,
                    ipv4_to_string((UINT32)flow_key.dst_addr),
                    flow_key.dst_port,
                    ip_ver,
                    proto_str,
                    executable,
                    pid,
                    packet_len
                );
            }

            if (!WinDivertSend(network_handle, packet, packet_len, nullptr, &addr)) {
                fprintf(stderr, "WinDivertSend(network) failed: %s\n", send_error_to_string(GetLastError()).c_str());
            }
        }
    }

    shutdown_throttle_system();
    WinDivertClose(network_handle);
}