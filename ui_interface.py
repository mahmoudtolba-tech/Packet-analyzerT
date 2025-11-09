"""
Modern Terminal UI for Packet Analyzer
Uses Rich library for beautiful, interactive terminal interface
"""

import sys
import time
from threading import Thread
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.text import Text
from rich.prompt import Prompt, IntPrompt, Confirm
from rich import box
from rich.align import Align

from packet_analyzer import (
    AdvancedPacketSniffer,
    PacketInfo,
    PacketStatistics,
    get_available_interfaces,
    check_root_privileges
)


class PacketAnalyzerUI:
    """Interactive terminal UI for packet analyzer"""

    def __init__(self):
        self.console = Console()
        self.sniffer: Optional[AdvancedPacketSniffer] = None
        self.capture_thread: Optional[Thread] = None
        self.live_display: Optional[Live] = None
        self.recent_packets = []
        self.max_display_packets = 15

    def show_banner(self):
        """Display welcome banner"""
        banner = """
  ╔═══════════════════════════════════════════════════════════╗
  ║                                                           ║
  ║         ADVANCED PACKET ANALYZER v2.0                     ║
  ║         Real-time Network Traffic Analysis                ║
  ║                                                           ║
  ╚═══════════════════════════════════════════════════════════╝
        """
        self.console.print(banner, style="bold cyan")

    def check_privileges(self) -> bool:
        """Check and warn about root privileges"""
        if not check_root_privileges():
            self.console.print("\n[bold red]⚠ WARNING:[/] This application requires root privileges!", style="bold yellow")
            self.console.print("Run with: [bold cyan]sudo python3 main.py[/]\n")
            return False
        return True

    def select_interface(self) -> Optional[str]:
        """Interactive interface selection"""
        interfaces = get_available_interfaces()

        if not interfaces:
            self.console.print("[bold red]Error:[/] No network interfaces found!")
            return None

        self.console.print("\n[bold cyan]Available Network Interfaces:[/]")

        # Create interface table
        table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED)
        table.add_column("No.", style="cyan", justify="center")
        table.add_column("Interface", style="green")

        for idx, iface in enumerate(interfaces, 1):
            table.add_row(str(idx), iface)

        self.console.print(table)

        while True:
            try:
                choice = IntPrompt.ask(
                    "\n[bold yellow]Select interface number[/]",
                    default=1
                )
                if 1 <= choice <= len(interfaces):
                    return interfaces[choice - 1]
                else:
                    self.console.print("[red]Invalid selection. Try again.[/]")
            except KeyboardInterrupt:
                return None

    def select_protocol(self) -> str:
        """Interactive protocol selection"""
        protocols = {
            '1': ('tcp', 'TCP - Transmission Control Protocol'),
            '2': ('udp', 'UDP - User Datagram Protocol'),
            '3': ('icmp', 'ICMP - Internet Control Message Protocol'),
            '4': ('arp', 'ARP - Address Resolution Protocol'),
            '5': ('all', 'All Protocols')
        }

        self.console.print("\n[bold cyan]Protocol Filter:[/]")

        table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED)
        table.add_column("No.", style="cyan", justify="center")
        table.add_column("Protocol", style="green")
        table.add_column("Description", style="white")

        for key, (proto, desc) in protocols.items():
            table.add_row(key, proto.upper(), desc)

        self.console.print(table)

        while True:
            choice = Prompt.ask(
                "\n[bold yellow]Select protocol[/]",
                choices=list(protocols.keys()),
                default='5'
            )
            return protocols[choice][0]

    def get_capture_params(self) -> tuple:
        """Get capture parameters from user"""
        self.console.print("\n[bold cyan]Capture Configuration:[/]")

        packet_count = IntPrompt.ask(
            "[yellow]Number of packets to capture[/] (0 = unlimited)",
            default=0
        )

        timeout = IntPrompt.ask(
            "[yellow]Capture timeout in seconds[/] (0 = no timeout)",
            default=60
        )

        return packet_count, timeout if timeout > 0 else None

    def create_live_display(self) -> Layout:
        """Create live display layout"""
        layout = Layout()

        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=3)
        )

        layout["main"].split_row(
            Layout(name="packets", ratio=2),
            Layout(name="stats", ratio=1)
        )

        return layout

    def update_display(self, layout: Layout, stats: PacketStatistics):
        """Update live display with current data"""
        # Header
        header_text = Text("⚡ CAPTURING PACKETS - Press Ctrl+C to stop", style="bold white on blue", justify="center")
        layout["header"].update(Panel(header_text, border_style="blue"))

        # Recent packets table
        packets_table = Table(
            title="Recent Packets",
            show_header=True,
            header_style="bold cyan",
            box=box.SIMPLE,
            expand=True
        )

        packets_table.add_column("Time", style="green", width=12)
        packets_table.add_column("Proto", style="cyan", width=6)
        packets_table.add_column("Src IP", style="yellow", width=15)
        packets_table.add_column("Dst IP", style="magenta", width=15)
        packets_table.add_column("Ports", style="white", width=12)
        packets_table.add_column("Size", style="blue", width=8, justify="right")

        for packet in self.recent_packets[-self.max_display_packets:]:
            time_str = packet.timestamp.split()[1]
            ports = ""
            if packet.src_port and packet.dst_port:
                ports = f"{packet.src_port}→{packet.dst_port}"

            packets_table.add_row(
                time_str,
                packet.protocol,
                packet.src_ip or "-",
                packet.dst_ip or "-",
                ports or "-",
                str(packet.length)
            )

        layout["packets"].update(Panel(packets_table, border_style="cyan", title="[bold]Live Feed"))

        # Statistics panel
        summary = stats.get_summary()

        stats_table = Table(show_header=False, box=None, padding=(0, 1))
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", style="white", justify="right")

        stats_table.add_row("📦 Total Packets", f"[bold green]{summary['total_packets']:,}")
        stats_table.add_row("💾 Total Bytes", f"[bold yellow]{summary['total_bytes']:,}")
        stats_table.add_row("⚡ Packets/sec", f"[bold cyan]{summary['packets_per_second']:.1f}")
        stats_table.add_row("🌐 Unique IPs", f"[bold magenta]{summary['unique_src_ips']}")
        stats_table.add_row("⏱ Runtime", f"[bold white]{summary['elapsed_seconds']:.1f}s")

        # Protocol breakdown
        proto_text = "\n[bold cyan]Protocol Distribution:[/]\n"
        for proto, count in summary['protocols'].items():
            percentage = (count / summary['total_packets'] * 100) if summary['total_packets'] > 0 else 0
            proto_text += f"  {proto}: [green]{count}[/] ([yellow]{percentage:.1f}%[/])\n"

        # Top talkers
        if summary['top_talkers']:
            proto_text += "\n[bold cyan]Top Talkers:[/]\n"
            for ip, count in summary['top_talkers'][:5]:
                proto_text += f"  {ip}: [green]{count}[/] packets\n"

        # Suspicious activity
        if summary['suspicious_patterns']:
            proto_text += "\n[bold red]⚠ Alerts:[/]\n"
            for pattern in summary['suspicious_patterns']:
                proto_text += f"  [red]• {pattern}[/]\n"

        stats_content = Table.grid()
        stats_content.add_row(stats_table)
        stats_content.add_row("")
        stats_content.add_row(Text.from_markup(proto_text))

        layout["stats"].update(Panel(stats_content, border_style="green", title="[bold]Statistics"))

        # Footer
        footer_text = Text(
            f"Interface: {self.sniffer.interface} | "
            f"Filter: {self.sniffer.protocol_filter or 'all'} | "
            f"Memory: {len(self.recent_packets)} packets",
            style="white on dark_blue",
            justify="center"
        )
        layout["footer"].update(Panel(footer_text, border_style="blue"))

    def packet_callback(self, packet_info: PacketInfo, stats: PacketStatistics):
        """Callback for new packets"""
        self.recent_packets.append(packet_info)

        # Limit memory
        if len(self.recent_packets) > 1000:
            self.recent_packets = self.recent_packets[-500:]

    def run_capture(self, interface: str, protocol: str, count: int, timeout: Optional[int]):
        """Run packet capture with live display"""
        self.sniffer = AdvancedPacketSniffer(interface, protocol)
        self.sniffer.set_callback(self.packet_callback)

        layout = self.create_live_display()

        try:
            with Live(layout, refresh_per_second=4, screen=True) as live:
                self.live_display = live

                def capture_thread():
                    self.sniffer.start_capture(count=count, timeout=timeout)

                thread = Thread(target=capture_thread, daemon=True)
                thread.start()

                # Update display while capturing
                while thread.is_alive():
                    self.update_display(layout, self.sniffer.statistics)
                    time.sleep(0.25)

                # Final update
                self.update_display(layout, self.sniffer.statistics)
                thread.join()

        except KeyboardInterrupt:
            self.console.print("\n[yellow]Stopping capture...[/]")
            self.sniffer.stop_capture()

    def show_export_menu(self):
        """Show export options menu"""
        if not self.sniffer or not self.sniffer.packets_data:
            self.console.print("\n[yellow]No packets captured to export.[/]")
            return

        self.console.print("\n[bold cyan]Export Options:[/]")

        table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED)
        table.add_column("No.", style="cyan", justify="center")
        table.add_column("Format", style="green")
        table.add_column("Description", style="white")

        table.add_row("1", "PCAP", "Standard packet capture format (for Wireshark)")
        table.add_row("2", "JSON", "Structured JSON format with full details")
        table.add_row("3", "CSV", "Comma-separated values (for Excel)")
        table.add_row("4", "Statistics", "JSON statistics summary")
        table.add_row("5", "All", "Export all formats")
        table.add_row("0", "Skip", "Don't export")

        self.console.print(table)

        choice = Prompt.ask(
            "\n[bold yellow]Select export format[/]",
            choices=['0', '1', '2', '3', '4', '5'],
            default='0'
        )

        if choice == '0':
            return

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        base_name = f"capture_{timestamp}"

        formats = []
        if choice == '1' or choice == '5':
            formats.append(('pcap', f"{base_name}.pcap"))
        if choice == '2' or choice == '5':
            formats.append(('json', f"{base_name}.json"))
        if choice == '3' or choice == '5':
            formats.append(('csv', f"{base_name}.csv"))
        if choice == '4' or choice == '5':
            formats.append(('stats', f"{base_name}_stats.json"))

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=self.console
        ) as progress:

            task = progress.add_task("[cyan]Exporting...", total=len(formats))

            for fmt, filename in formats:
                progress.update(task, description=f"[cyan]Exporting {fmt.upper()}...")

                try:
                    if fmt == 'pcap':
                        self.sniffer.export_to_pcap(filename)
                    elif fmt == 'json':
                        self.sniffer.export_to_json(filename)
                    elif fmt == 'csv':
                        self.sniffer.export_to_csv(filename)
                    elif fmt == 'stats':
                        self.sniffer.export_statistics(filename)

                    self.console.print(f"  ✓ [green]Saved:[/] {filename}")
                except Exception as e:
                    self.console.print(f"  ✗ [red]Error saving {filename}:[/] {e}")

                progress.advance(task)

        self.console.print("\n[bold green]Export complete![/]")

    def show_statistics_summary(self):
        """Display detailed statistics summary"""
        if not self.sniffer:
            return

        summary = self.sniffer.statistics.get_summary()

        self.console.print("\n" + "=" * 60)
        self.console.print("[bold cyan]CAPTURE SUMMARY[/]".center(60))
        self.console.print("=" * 60 + "\n")

        # Main stats
        main_table = Table(show_header=False, box=box.ROUNDED, title="Overview")
        main_table.add_column("Metric", style="cyan", width=30)
        main_table.add_column("Value", style="white", justify="right")

        main_table.add_row("Total Packets Captured", f"[bold green]{summary['total_packets']:,}")
        main_table.add_row("Total Bytes", f"[bold yellow]{summary['total_bytes']:,}")
        main_table.add_row("Capture Duration", f"[bold white]{summary['elapsed_seconds']:.2f} seconds")
        main_table.add_row("Average Packets/sec", f"[bold cyan]{summary['packets_per_second']:.2f}")
        main_table.add_row("Average Bytes/sec", f"[bold magenta]{summary['bytes_per_second']:.2f}")
        main_table.add_row("Unique Source IPs", f"[bold green]{summary['unique_src_ips']}")
        main_table.add_row("Unique Destination IPs", f"[bold yellow]{summary['unique_dst_ips']}")

        self.console.print(main_table)

        # Protocol distribution
        if summary['protocols']:
            self.console.print("\n[bold cyan]Protocol Distribution:[/]")
            proto_table = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE)
            proto_table.add_column("Protocol", style="cyan")
            proto_table.add_column("Count", style="green", justify="right")
            proto_table.add_column("Percentage", style="yellow", justify="right")

            for proto, count in sorted(summary['protocols'].items(), key=lambda x: x[1], reverse=True):
                percentage = (count / summary['total_packets'] * 100)
                proto_table.add_row(proto, f"{count:,}", f"{percentage:.2f}%")

            self.console.print(proto_table)

        # Top talkers
        if summary['top_talkers']:
            self.console.print("\n[bold cyan]Top Source IPs:[/]")
            talker_table = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE)
            talker_table.add_column("Rank", style="cyan", justify="center")
            talker_table.add_column("IP Address", style="green")
            talker_table.add_column("Packet Count", style="yellow", justify="right")

            for idx, (ip, count) in enumerate(summary['top_talkers'], 1):
                talker_table.add_row(str(idx), ip, f"{count:,}")

            self.console.print(talker_table)

        # Alerts
        if summary['suspicious_patterns']:
            self.console.print("\n[bold red]⚠ Security Alerts:[/]")
            for pattern in summary['suspicious_patterns']:
                self.console.print(f"  [red]• {pattern}[/]")

        self.console.print("\n" + "=" * 60 + "\n")

    def run(self):
        """Main UI flow"""
        self.show_banner()

        if not self.check_privileges():
            return 1

        try:
            # Select interface
            interface = self.select_interface()
            if not interface:
                return 1

            self.console.print(f"\n[green]✓[/] Selected interface: [bold cyan]{interface}[/]")

            # Select protocol
            protocol = self.select_protocol()
            self.console.print(f"[green]✓[/] Protocol filter: [bold cyan]{protocol}[/]")

            # Get capture params
            count, timeout = self.get_capture_params()

            # Confirm start
            self.console.print(f"\n[bold yellow]Ready to start capture![/]")
            self.console.print(f"  Interface: [cyan]{interface}[/]")
            self.console.print(f"  Protocol: [cyan]{protocol}[/]")
            self.console.print(f"  Packets: [cyan]{count if count > 0 else 'unlimited'}[/]")
            self.console.print(f"  Timeout: [cyan]{timeout if timeout else 'none'}[/] seconds\n")

            if not Confirm.ask("Start capture?", default=True):
                self.console.print("[yellow]Cancelled.[/]")
                return 0

            # Run capture
            self.run_capture(interface, protocol, count, timeout)

            # Show summary
            self.show_statistics_summary()

            # Export options
            if Confirm.ask("\nWould you like to export the captured data?", default=True):
                self.show_export_menu()

            self.console.print("\n[bold green]Thank you for using Advanced Packet Analyzer![/]\n")
            return 0

        except KeyboardInterrupt:
            self.console.print("\n\n[yellow]Operation cancelled by user.[/]")
            return 1
        except Exception as e:
            self.console.print(f"\n[bold red]Error:[/] {e}")
            import traceback
            traceback.print_exc()
            return 1


def main():
    """Entry point for UI"""
    ui = PacketAnalyzerUI()
    return ui.run()


if __name__ == "__main__":
    sys.exit(main())
