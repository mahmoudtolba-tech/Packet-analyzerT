"""
Advanced Packet Analyzer - Core Module
Provides comprehensive packet capture and analysis capabilities
"""

import logging
import json
import csv
from datetime import datetime
from collections import defaultdict, Counter
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, asdict
from threading import Lock
import pickle

try:
    from scapy.all import *
except ImportError:
    print("ERROR: scapy is not installed. Run setup.sh first.")
    sys.exit(1)

# Suppress scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)


@dataclass
class PacketInfo:
    """Structured packet information"""
    timestamp: str
    protocol: str
    src_mac: str
    dst_mac: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    length: int = 0
    flags: Optional[str] = None
    payload_size: int = 0

    def to_dict(self) -> Dict:
        return asdict(self)

    def to_csv_row(self) -> List:
        return [
            self.timestamp, self.protocol, self.src_mac, self.dst_mac,
            self.src_ip or '', self.dst_ip or '',
            self.src_port or '', self.dst_port or '',
            self.length, self.flags or '', self.payload_size
        ]


class PacketStatistics:
    """Real-time packet statistics tracker"""

    def __init__(self):
        self.lock = Lock()
        self.total_packets = 0
        self.protocol_counts = Counter()
        self.ip_src_counts = Counter()
        self.ip_dst_counts = Counter()
        self.port_counts = Counter()
        self.total_bytes = 0
        self.start_time = datetime.now()
        self.suspicious_patterns = []

    def update(self, packet_info: PacketInfo):
        """Update statistics with new packet"""
        with self.lock:
            self.total_packets += 1
            self.protocol_counts[packet_info.protocol] += 1
            self.total_bytes += packet_info.length

            if packet_info.src_ip:
                self.ip_src_counts[packet_info.src_ip] += 1
            if packet_info.dst_ip:
                self.ip_dst_counts[packet_info.dst_ip] += 1
            if packet_info.dst_port:
                self.port_counts[packet_info.dst_port] += 1

            # Detect suspicious patterns
            self._detect_anomalies(packet_info)

    def _detect_anomalies(self, packet_info: PacketInfo):
        """Simple anomaly detection"""
        # Port scanning detection (same source, many different ports)
        if packet_info.src_ip:
            src_ip = packet_info.src_ip
            if self.ip_src_counts[src_ip] > 100:
                # Check if scanning multiple ports
                unique_ports = len([p for p in self.port_counts if self.port_counts[p] > 0])
                if unique_ports > 50:
                    pattern = f"Possible port scan from {src_ip}"
                    if pattern not in self.suspicious_patterns:
                        self.suspicious_patterns.append(pattern)

    def get_top_talkers(self, n=10) -> List[tuple]:
        """Get top N source IPs by packet count"""
        with self.lock:
            return self.ip_src_counts.most_common(n)

    def get_top_protocols(self, n=5) -> List[tuple]:
        """Get top N protocols"""
        with self.lock:
            return self.protocol_counts.most_common(n)

    def get_summary(self) -> Dict:
        """Get statistics summary"""
        with self.lock:
            elapsed = (datetime.now() - self.start_time).total_seconds()
            pps = self.total_packets / elapsed if elapsed > 0 else 0
            bps = self.total_bytes / elapsed if elapsed > 0 else 0

            return {
                'total_packets': self.total_packets,
                'total_bytes': self.total_bytes,
                'elapsed_seconds': round(elapsed, 2),
                'packets_per_second': round(pps, 2),
                'bytes_per_second': round(bps, 2),
                'unique_src_ips': len(self.ip_src_counts),
                'unique_dst_ips': len(self.ip_dst_counts),
                'protocols': dict(self.protocol_counts),
                'top_talkers': self.get_top_talkers(5),
                'suspicious_patterns': self.suspicious_patterns
            }


class AdvancedPacketSniffer:
    """Advanced packet sniffer with comprehensive analysis"""

    def __init__(self, interface: str, protocol_filter: Optional[str] = None):
        self.interface = interface
        self.protocol_filter = protocol_filter
        self.packets_data: List[PacketInfo] = []
        self.raw_packets: List = []
        self.statistics = PacketStatistics()
        self.running = False
        self.callback: Optional[Callable] = None
        self.max_packets_memory = 10000  # Limit memory usage

    def set_callback(self, callback: Callable):
        """Set callback for real-time packet processing"""
        self.callback = callback

    def _parse_packet(self, packet) -> Optional[PacketInfo]:
        """Parse packet into structured information"""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

            # Basic layer 2 info
            if not packet.haslayer(Ether):
                return None

            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst
            length = len(packet)

            # Determine protocol and extract details
            protocol = "Unknown"
            src_ip = dst_ip = None
            src_port = dst_port = None
            flags = None
            payload_size = 0

            # IP layer
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst

                # TCP
                if packet.haslayer(TCP):
                    protocol = "TCP"
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    flags = packet[TCP].flags
                    if packet.haslayer(Raw):
                        payload_size = len(packet[Raw].load)

                # UDP
                elif packet.haslayer(UDP):
                    protocol = "UDP"
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    if packet.haslayer(Raw):
                        payload_size = len(packet[Raw].load)

                # ICMP
                elif packet.haslayer(ICMP):
                    protocol = "ICMP"

            # ARP
            elif packet.haslayer(ARP):
                protocol = "ARP"
                src_ip = packet[ARP].psrc
                dst_ip = packet[ARP].pdst

            # DHCP/BOOTP
            elif packet.haslayer(BOOTP):
                protocol = "DHCP"
                if packet.haslayer(IP):
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst

            return PacketInfo(
                timestamp=timestamp,
                protocol=protocol,
                src_mac=src_mac,
                dst_mac=dst_mac,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                length=length,
                flags=str(flags) if flags else None,
                payload_size=payload_size
            )

        except Exception as e:
            logging.error(f"Error parsing packet: {e}")
            return None

    def _packet_handler(self, packet):
        """Handle captured packet"""
        packet_info = self._parse_packet(packet)

        if packet_info:
            # Update statistics
            self.statistics.update(packet_info)

            # Store packet data (with memory limit)
            if len(self.packets_data) < self.max_packets_memory:
                self.packets_data.append(packet_info)
                self.raw_packets.append(packet)

            # Call callback for real-time processing
            if self.callback:
                self.callback(packet_info, self.statistics)

    def start_capture(self, count: int = 0, timeout: Optional[int] = None):
        """Start packet capture"""
        self.running = True

        try:
            # Set interface to promiscuous mode
            os.system(f"ip link set {self.interface} promisc on 2>/dev/null")

            # Build filter
            bpf_filter = None
            if self.protocol_filter and self.protocol_filter != "all":
                bpf_filter = self.protocol_filter

            # Start sniffing
            sniff(
                iface=self.interface,
                filter=bpf_filter,
                prn=self._packet_handler,
                count=count if count > 0 else 0,
                timeout=timeout,
                store=False  # Don't store in memory, we handle it
            )

        except Exception as e:
            logging.error(f"Capture error: {e}")
            raise
        finally:
            self.running = False

    def stop_capture(self):
        """Stop packet capture"""
        self.running = False

    def export_to_json(self, filename: str):
        """Export captured packets to JSON"""
        data = {
            'capture_info': {
                'interface': self.interface,
                'filter': self.protocol_filter,
                'total_packets': len(self.packets_data)
            },
            'statistics': self.statistics.get_summary(),
            'packets': [p.to_dict() for p in self.packets_data]
        }

        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)

    def export_to_csv(self, filename: str):
        """Export captured packets to CSV"""
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Timestamp', 'Protocol', 'Src MAC', 'Dst MAC',
                'Src IP', 'Dst IP', 'Src Port', 'Dst Port',
                'Length', 'Flags', 'Payload Size'
            ])

            for packet in self.packets_data:
                writer.writerow(packet.to_csv_row())

    def export_to_pcap(self, filename: str):
        """Export captured packets to PCAP format"""
        if self.raw_packets:
            wrpcap(filename, self.raw_packets)

    def export_statistics(self, filename: str):
        """Export statistics to JSON"""
        stats = self.statistics.get_summary()
        with open(filename, 'w') as f:
            json.dump(stats, f, indent=2)

    def search_packets(self, **criteria) -> List[PacketInfo]:
        """Search packets by criteria"""
        results = []

        for packet in self.packets_data:
            match = True

            if 'src_ip' in criteria and packet.src_ip != criteria['src_ip']:
                match = False
            if 'dst_ip' in criteria and packet.dst_ip != criteria['dst_ip']:
                match = False
            if 'protocol' in criteria and packet.protocol != criteria['protocol']:
                match = False
            if 'port' in criteria:
                if packet.src_port != criteria['port'] and packet.dst_port != criteria['port']:
                    match = False

            if match:
                results.append(packet)

        return results

    def get_conversation_pairs(self) -> List[tuple]:
        """Get unique IP conversation pairs"""
        conversations = set()

        for packet in self.packets_data:
            if packet.src_ip and packet.dst_ip:
                # Normalize (always smaller IP first)
                pair = tuple(sorted([packet.src_ip, packet.dst_ip]))
                conversations.add(pair)

        return list(conversations)


def get_available_interfaces() -> List[str]:
    """Get list of available network interfaces"""
    try:
        interfaces = get_if_list()
        return [iface for iface in interfaces if iface != 'lo']
    except:
        # Fallback method
        try:
            return os.listdir('/sys/class/net/')
        except:
            return []


def check_root_privileges() -> bool:
    """Check if running with root privileges"""
    return os.geteuid() == 0
