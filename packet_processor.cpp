/**
 * Advanced Packet Processor - C++ Performance Module
 *
 * High-performance packet processing routines for:
 * - Fast packet parsing
 * - Protocol detection
 * - Statistical analysis
 * - Pattern matching
 *
 * This module can be compiled as a shared library and called from Python
 * for performance-critical operations.
 */

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <cstring>
#include <arpa/inet.h>

// Packet header structures
#pragma pack(push, 1)

struct EthernetHeader {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;
};

struct IPv4Header {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
};

struct TCPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset_reserved;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
};

struct UDPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};

#pragma pack(pop)

// Protocol identifiers
enum Protocol {
    PROTO_UNKNOWN = 0,
    PROTO_TCP = 6,
    PROTO_UDP = 17,
    PROTO_ICMP = 1,
    PROTO_ARP = 0x0806
};

// Packet statistics structure
struct PacketStats {
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t icmp_packets;
    uint64_t other_packets;
    std::map<uint32_t, uint32_t> src_ip_counts;
    std::map<uint16_t, uint32_t> port_counts;
};

class FastPacketProcessor {
private:
    PacketStats stats;

public:
    FastPacketProcessor() {
        reset_stats();
    }

    void reset_stats() {
        stats.total_packets = 0;
        stats.total_bytes = 0;
        stats.tcp_packets = 0;
        stats.udp_packets = 0;
        stats.icmp_packets = 0;
        stats.other_packets = 0;
        stats.src_ip_counts.clear();
        stats.port_counts.clear();
    }

    // Convert MAC address to string
    static std::string mac_to_string(const uint8_t* mac) {
        char buffer[18];
        snprintf(buffer, sizeof(buffer), "%02x:%02x:%02x:%02x:%02x:%02x",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return std::string(buffer);
    }

    // Convert IP address to string
    static std::string ip_to_string(uint32_t ip) {
        char buffer[16];
        uint8_t* bytes = (uint8_t*)&ip;
        snprintf(buffer, sizeof(buffer), "%d.%d.%d.%d",
                bytes[0], bytes[1], bytes[2], bytes[3]);
        return std::string(buffer);
    }

    // Fast protocol detection
    uint8_t detect_protocol(const uint8_t* packet, size_t length) {
        if (length < sizeof(EthernetHeader) + sizeof(IPv4Header)) {
            return PROTO_UNKNOWN;
        }

        const EthernetHeader* eth = (const EthernetHeader*)packet;
        uint16_t ethertype = ntohs(eth->ethertype);

        // Check if IPv4
        if (ethertype == 0x0800) {
            const IPv4Header* ip = (const IPv4Header*)(packet + sizeof(EthernetHeader));
            return ip->protocol;
        }

        // ARP
        if (ethertype == 0x0806) {
            return PROTO_ARP;
        }

        return PROTO_UNKNOWN;
    }

    // Process packet and update statistics
    bool process_packet(const uint8_t* packet, size_t length) {
        if (length < sizeof(EthernetHeader)) {
            return false;
        }

        stats.total_packets++;
        stats.total_bytes += length;

        const EthernetHeader* eth = (const EthernetHeader*)packet;
        uint16_t ethertype = ntohs(eth->ethertype);


        if (ethertype == 0x0800 && length >= sizeof(EthernetHeader) + sizeof(IPv4Header)) {
            const IPv4Header* ip = (const IPv4Header*)(packet + sizeof(EthernetHeader));


            stats.src_ip_counts[ip->src_ip]++;

            uint8_t protocol = ip->protocol;
            size_t ip_header_len = (ip->version_ihl & 0x0F) * 4;


            if (protocol == PROTO_TCP) {
                stats.tcp_packets++;

                if (length >= sizeof(EthernetHeader) + ip_header_len + sizeof(TCPHeader)) {
                    const TCPHeader* tcp = (const TCPHeader*)(packet + sizeof(EthernetHeader) + ip_header_len);
                    stats.port_counts[ntohs(tcp->dst_port)]++;
                }
            }
            // Process UDP
            else if (protocol == PROTO_UDP) {
                stats.udp_packets++;

                if (length >= sizeof(EthernetHeader) + ip_header_len + sizeof(UDPHeader)) {
                    const UDPHeader* udp = (const UDPHeader*)(packet + sizeof(EthernetHeader) + ip_header_len);
                    stats.port_counts[ntohs(udp->dst_port)]++;
                }
            }

            else if (protocol == PROTO_ICMP) {
                stats.icmp_packets++;
            }
            else {
                stats.other_packets++;
            }
        }
        else {
            stats.other_packets++;
        }

        return true;
    }

    // Extract packet information
    struct PacketInfo {
        std::string src_mac;
        std::string dst_mac;
        std::string src_ip;
        std::string dst_ip;
        uint16_t src_port;
        uint16_t dst_port;
        uint8_t protocol;
        size_t length;
    };

    PacketInfo extract_info(const uint8_t* packet, size_t length) {
        PacketInfo info = {};
        info.src_port = 0;
        info.dst_port = 0;
        info.protocol = PROTO_UNKNOWN;
        info.length = length;

        if (length < sizeof(EthernetHeader)) {
            return info;
        }

        const EthernetHeader* eth = (const EthernetHeader*)packet;
        info.src_mac = mac_to_string(eth->src_mac);
        info.dst_mac = mac_to_string(eth->dst_mac);

        uint16_t ethertype = ntohs(eth->ethertype);

        // IPv4
        if (ethertype == 0x0800 && length >= sizeof(EthernetHeader) + sizeof(IPv4Header)) {
            const IPv4Header* ip = (const IPv4Header*)(packet + sizeof(EthernetHeader));
            info.src_ip = ip_to_string(ip->src_ip);
            info.dst_ip = ip_to_string(ip->dst_ip);
            info.protocol = ip->protocol;

            size_t ip_header_len = (ip->version_ihl & 0x0F) * 4;

            // TCP
            if (ip->protocol == PROTO_TCP &&
                length >= sizeof(EthernetHeader) + ip_header_len + sizeof(TCPHeader)) {
                const TCPHeader* tcp = (const TCPHeader*)(packet + sizeof(EthernetHeader) + ip_header_len);
                info.src_port = ntohs(tcp->src_port);
                info.dst_port = ntohs(tcp->dst_port);
            }
            // UDP
            else if (ip->protocol == PROTO_UDP &&
                     length >= sizeof(EthernetHeader) + ip_header_len + sizeof(UDPHeader)) {
                const UDPHeader* udp = (const UDPHeader*)(packet + sizeof(EthernetHeader) + ip_header_len);
                info.src_port = ntohs(udp->src_port);
                info.dst_port = ntohs(udp->dst_port);
            }
        }

        return info;
    }

    // Get current statistics
    const PacketStats& get_stats() const {
        return stats;
    }

    // Detect port scanning behavior
    bool detect_port_scan(uint32_t src_ip, uint32_t threshold = 50) {
        if (stats.src_ip_counts.find(src_ip) == stats.src_ip_counts.end()) {
            return false;
        }

        // If a single source IP has contacted many different ports
        uint32_t unique_ports = 0;
        for (const auto& [port, count] : stats.port_counts) {
            if (count > 0) unique_ports++;
        }

        return (stats.src_ip_counts[src_ip] > threshold && unique_ports > 30);
    }

    // Simple payload pattern matching
    bool match_pattern(const uint8_t* packet, size_t length,
                      const uint8_t* pattern, size_t pattern_len) {
        if (length < pattern_len) return false;

        for (size_t i = 0; i <= length - pattern_len; i++) {
            if (memcmp(packet + i, pattern, pattern_len) == 0) {
                return true;
            }
        }
        return false;
    }

    // Calculate packet rate
    double calculate_packet_rate(double elapsed_seconds) {
        if (elapsed_seconds <= 0) return 0.0;
        return static_cast<double>(stats.total_packets) / elapsed_seconds;
    }

    // Calculate bandwidth
    double calculate_bandwidth(double elapsed_seconds) {
        if (elapsed_seconds <= 0) return 0.0;
        return static_cast<double>(stats.total_bytes) / elapsed_seconds;
    }
};

// C interface for Python integration
extern "C" {
    FastPacketProcessor* processor_new() {
        return new FastPacketProcessor();
    }

    void processor_delete(FastPacketProcessor* proc) {
        delete proc;
    }

    void processor_reset(FastPacketProcessor* proc) {
        proc->reset_stats();
    }

    bool processor_process_packet(FastPacketProcessor* proc,
                                  const uint8_t* packet, size_t length) {
        return proc->process_packet(packet, length);
    }

    uint64_t processor_get_total_packets(FastPacketProcessor* proc) {
        return proc->get_stats().total_packets;
    }

    uint64_t processor_get_total_bytes(FastPacketProcessor* proc) {
        return proc->get_stats().total_bytes;
    }

    double processor_get_packet_rate(FastPacketProcessor* proc, double elapsed) {
        return proc->calculate_packet_rate(elapsed);
    }

    double processor_get_bandwidth(FastPacketProcessor* proc, double elapsed) {
        return proc->calculate_bandwidth(elapsed);
    }
}

// Test main (for standalone compilation)
#ifdef BUILD_STANDALONE
int main() {
    std::cout << "Fast Packet Processor - C++ Module" << std::endl;
    std::cout << "This module provides high-performance packet processing." << std::endl;
    std::cout << "Compile as shared library: g++ -O3 -shared -fPIC -o packet_processor.so packet_processor.cpp" << std::endl;

    FastPacketProcessor proc;
    std::cout << "Processor initialized successfully!" << std::endl;

    return 0;
}
#endif
