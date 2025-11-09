# Advanced Packet Analyzer v2.0

<div align="center">

**Professional Network Traffic Capture and Analysis Tool**

[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Scapy](https://img.shields.io/badge/Scapy-2.5+-orange.svg)](https://scapy.net/)

*A modern, feature-rich packet sniffer with beautiful terminal UI and advanced analysis capabilities*

</div>

---

## Features

### 🎨 Modern Terminal UI
- **Beautiful interface** powered by Rich library
- **Real-time packet display** with live statistics
- **Interactive menus** for easy configuration
- **Color-coded protocols** for quick identification
- **Progress indicators** and status updates

### 📊 Advanced Analysis
- **Deep packet inspection** - Extract detailed information from packets
- **Protocol statistics** - Real-time breakdown of traffic by protocol
- **Traffic analysis** - Identify top talkers and conversation pairs
- **Anomaly detection** - Basic security alerts (port scanning, unusual patterns)
- **Bandwidth monitoring** - Track bytes/packets per second

### 💾 Multiple Export Formats
- **PCAP** - Standard format for Wireshark and other tools
- **JSON** - Structured data for programmatic analysis
- **CSV** - Spreadsheet-compatible format
- **Statistics reports** - Comprehensive traffic summaries

### ⚡ High Performance
- **Optimized Python core** using Scapy
- **Optional C++ module** for performance-critical operations
- **Memory-efficient** packet buffering
- **Multi-threaded** capture and display

### 🔍 Protocol Support
- **TCP** - Full analysis with port and flag information
- **UDP** - Source/destination tracking
- **ICMP** - Network diagnostics
- **ARP** - Layer 2 address resolution
- **DHCP/BOOTP** - Network configuration
- **And more** - Extensible architecture

---

## Installation

### Quick Setup (Automated)

The easiest way to get started is using the automated setup script:

```bash
# Clone or download the repository
cd PacketCapture

# Run setup script (creates venv and installs everything)
chmod +x setup.sh
./setup.sh
```

The setup script will:
- ✅ Check Python version (3.7+ required)
- ✅ Create a virtual environment
- ✅ Install all dependencies
- ✅ Compile C++ performance module (optional)
- ✅ Create a launcher script

### Manual Installation

If you prefer manual setup:

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# (Optional) Compile C++ module for better performance
g++ -O3 -shared -fPIC -o packet_processor.so packet_processor.cpp
```

### Requirements

- **Python 3.7+**
- **Root/sudo privileges** (required for packet capture)
- **pip** (Python package installer)
- **Linux** (tested on Ubuntu/Debian, should work on most distributions)

**Optional:**
- **g++** compiler (for C++ performance module)

---

## Usage

### Quick Start

```bash
# Using the launcher (recommended)
./run.sh

# Or manually with venv
source venv/bin/activate
sudo python3 main.py
```

### Interactive Mode

The tool will guide you through:

1. **Select Network Interface**
   - Choose from available interfaces (eth0, wlan0, etc.)

2. **Choose Protocol Filter**
   - TCP, UDP, ICMP, ARP, or All protocols

3. **Configure Capture**
   - Number of packets (0 = unlimited)
   - Timeout duration (0 = no timeout)

4. **Monitor Traffic**
   - Real-time packet feed
   - Live statistics
   - Security alerts

5. **Export Results**
   - Choose format(s)
   - Save captures for later analysis

### Example Session

```
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║         ADVANCED PACKET ANALYZER v2.0                     ║
║         Real-time Network Traffic Analysis                ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝

Available Network Interfaces:
┌────┬───────────┐
│ No.│ Interface │
├────┼───────────┤
│ 1  │ eth0      │
│ 2  │ wlan0     │
└────┴───────────┘

Select interface number [1]: 1
✓ Selected interface: eth0

Protocol Filter:
┌────┬──────┬────────────────────────────────────────────┐
│ No.│ Proto│ Description                                │
├────┼──────┼────────────────────────────────────────────┤
│ 1  │ TCP  │ Transmission Control Protocol              │
│ 2  │ UDP  │ User Datagram Protocol                     │
│ 3  │ ICMP │ Internet Control Message Protocol          │
│ 4  │ ARP  │ Address Resolution Protocol                │
│ 5  │ ALL  │ All Protocols                              │
└────┴──────┴────────────────────────────────────────────┘

Select protocol [5]: 5
✓ Protocol filter: all

Capture Configuration:
Number of packets to capture (0 = unlimited): 1000
Capture timeout in seconds (0 = no timeout): 60

Ready to start capture!
  Interface: eth0
  Protocol: all
  Packets: 1000
  Timeout: 60 seconds

Start capture? [Y/n]: y

[Live capture screen with real-time updates...]
```

---

## Architecture

```
PacketCapture/
│
├── main.py                  # Entry point
├── packet_analyzer.py       # Core packet analysis engine
├── ui_interface.py          # Rich-based terminal UI
├── packet_processor.cpp     # C++ performance module (optional)
│
├── requirements.txt         # Python dependencies
├── setup.sh                 # Automated setup script
├── run.sh                   # Launcher script
│
├── S1.py                    # Original simple version (legacy)
└── README.md                # This file
```

### Components

#### `packet_analyzer.py`
- Core packet capture and analysis
- Statistics tracking and anomaly detection
- Export functionality (PCAP, JSON, CSV)
- Search and filtering capabilities

#### `ui_interface.py`
- Modern terminal UI using Rich library
- Interactive menus and prompts
- Real-time packet display
- Statistics visualization

#### `packet_processor.cpp` (Optional)
- High-performance C++ module
- Fast packet parsing
- Protocol detection
- Pattern matching

---

## Advanced Features

### Security Alerts

The analyzer includes basic intrusion detection:

- **Port Scanning Detection** - Identifies hosts scanning multiple ports
- **Traffic Anomalies** - Unusual packet patterns
- **High-volume Sources** - Hosts sending excessive traffic

### Statistics Analysis

Comprehensive traffic analysis:

```json
{
  "total_packets": 15234,
  "total_bytes": 12485672,
  "packets_per_second": 253.9,
  "bytes_per_second": 208094.5,
  "protocols": {
    "TCP": 12456,
    "UDP": 2341,
    "ICMP": 437
  },
  "top_talkers": [
    ["192.168.1.100", 8234],
    ["192.168.1.50", 3456]
  ],
  "suspicious_patterns": [
    "Possible port scan from 192.168.1.200"
  ]
}
```

### Export Formats

**PCAP Format:**
- Standard packet capture format
- Open with Wireshark, tcpdump, etc.
- Preserves raw packet data

**JSON Format:**
- Structured, human-readable
- Includes metadata and statistics
- Easy to parse programmatically

**CSV Format:**
- Spreadsheet compatible
- Import into Excel, Google Sheets
- Simple tabular format

---

## Comparison: Original vs Advanced

| Feature | S1.py (Original) | v2.0 (Advanced) |
|---------|------------------|-----------------|
| UI | Basic text prompts | Rich terminal UI |
| Real-time display | No | Yes |
| Statistics | No | Yes |
| Export formats | Text log only | PCAP, JSON, CSV |
| Anomaly detection | No | Yes |
| Performance | Basic | Optimized + C++ |
| Memory management | Unlimited | Smart buffering |
| Error handling | Basic | Comprehensive |
| Documentation | Minimal | Extensive |

---

## Troubleshooting

### "Permission Denied" Error

Packet capture requires root privileges:

```bash
# Make sure to run with sudo
sudo python3 main.py

# Or use the launcher
./run.sh  # automatically uses sudo
```

### "scapy not found" Error

Install dependencies:

```bash
source venv/bin/activate
pip install -r requirements.txt
```

### "No interfaces found" Error

Check network interfaces:

```bash
ip link show
# or
ifconfig -a
```

Make sure you're running on Linux. This tool is designed for Linux systems.

### High CPU Usage

For better performance:

1. Compile the C++ module:
   ```bash
   g++ -O3 -shared -fPIC -o packet_processor.so packet_processor.cpp
   ```

2. Use specific protocol filters instead of "all"

3. Limit packet count for large captures

---

## Security & Legal Notice

⚠️ **IMPORTANT:** This tool is for **educational and authorized use only**.

- Only capture traffic on networks you own or have permission to monitor
- Packet sniffing may be illegal without authorization
- Some jurisdictions have strict laws about network monitoring
- Always obtain proper authorization before use
- Use responsibly and ethically

This tool is intended for:
- Network administrators troubleshooting issues
- Security researchers (with authorization)
- Students learning about networking
- Developers testing applications
- Penetration testers (with client authorization)

---

## Contributing

Contributions are welcome! Areas for improvement:

- Additional protocol parsers
- More sophisticated anomaly detection
- GUI version (tkinter/PyQt)
- Windows/macOS support
- Performance optimizations
- Additional export formats

---

## License

MIT License - See LICENSE file for details

---

## Author

Created as an educational project to demonstrate:
- Network packet analysis
- Modern Python development practices
- Terminal UI design with Rich
- C++/Python integration
- Security tool development

---

## Acknowledgments

- **Scapy** - Powerful packet manipulation library
- **Rich** - Beautiful terminal formatting
- **Python Community** - Excellent documentation and libraries

---

## Version History

**v2.0** (Current)
- Complete rewrite with modern UI
- Advanced statistics and analysis
- Multiple export formats
- C++ performance module
- Anomaly detection
- Automated setup

**v1.0** (S1.py)
- Basic packet capture
- Simple text logging
- Manual configuration

---

**Happy Packet Analyzing! 📡🔍**
