#!/usr/bin/env python3
"""
Network Traffic Analyzer
Analyzes network traffic using Wireshark/tshark and generates analytics with graphs
"""

import pyshark
import matpl

matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from collections import Counter, defaultdict
import argparse
import sys
import time
from datetime import datetime
import warnings

warnings.filterwarnings('ignore')


class NetworkTrafficAnalyzer:
    def __init__(self, interface=None, pcap_file=None, packet_count=1000):
        self.interface = interface
        self.pcap_file = pcap_file
        self.packet_count = packet_count
        self.packets = []
        self.protocols = Counter()
        self.src_ips = Counter()
        self.dst_ips = Counter()
        self.packet_sizes = []
        self.timestamps = []
        self.ports = Counter()
        self.tcp_flags = Counter()

    def capture_packets(self):
        """Capture packets from interface or read from pcap file"""
        print(f"{'Reading from file' if self.pcap_file else 'Capturing packets'}...")

        try:
            if self.pcap_file:
                capture = pyshark.FileCapture(self.pcap_file)
            else:
                capture = pyshark.LiveCapture(interface=self.interface)

            packet_counter = 0
            for packet in capture:
                if packet_counter >= self.packet_count:
                    break

                self.packets.append(packet)
                self._analyze_packet(packet)
                packet_counter += 1

                if packet_counter % 100 == 0:
                    print(f"Processed {packet_counter} packets...")

            capture.close()
            print(f"Analysis complete! Processed {len(self.packets)} packets.")

        except Exception as e:
            print(f"Error capturing packets: {e}")
            sys.exit(1)

    def _analyze_packet(self, packet):
        """Analyze individual packet and extract information"""
        try:
            # Protocol analysis
            if hasattr(packet, 'highest_layer'):
                self.protocols[packet.highest_layer] += 1

            # Packet size
            if hasattr(packet, 'length'):
                self.packet_sizes.append(int(packet.length))

            # Timestamp
            if hasattr(packet, 'sniff_time'):
                self.timestamps.append(packet.sniff_time)

            # IP layer analysis
            if hasattr(packet, 'ip'):
                self.src_ips[packet.ip.src] += 1
                self.dst_ips[packet.ip.dst] += 1

            # TCP analysis
            if hasattr(packet, 'tcp'):
                self.ports[f"TCP:{packet.tcp.srcport}"] += 1
                self.ports[f"TCP:{packet.tcp.dstport}"] += 1

                # TCP flags
                if hasattr(packet.tcp, 'flags'):
                    flags = int(packet.tcp.flags, 16)
                    if flags & 0x02: self.tcp_flags['SYN'] += 1
                    if flags & 0x10: self.tcp_flags['ACK'] += 1
                    if flags & 0x01: self.tcp_flags['FIN'] += 1
                    if flags & 0x04: self.tcp_flags['RST'] += 1
                    if flags & 0x08: self.tcp_flags['PSH'] += 1

            # UDP analysis
            if hasattr(packet, 'udp'):
                self.ports[f"UDP:{packet.udp.srcport}"] += 1
                self.ports[f"UDP:{packet.udp.dstport}"] += 1

        except Exception as e:
            # Skip problematic packets
            pass

    def generate_statistics(self):
        """Generate and display traffic statistics"""
        print("\n" + "=" * 60)
        print("NETWORK TRAFFIC ANALYSIS REPORT")
        print("=" * 60)

        print(f"\n📊 GENERAL STATISTICS")
        print(f"Total Packets Analyzed: {len(self.packets)}")
        print(f"Average Packet Size: {np.mean(self.packet_sizes):.2f} bytes")
        print(f"Total Traffic Volume: {sum(self.packet_sizes):,} bytes")
        print(f"Analysis Duration: {(self.timestamps[-1] - self.timestamps[0]).total_seconds():.2f} seconds")

        print(f"\n🌐 TOP PROTOCOLS")
        for protocol, count in self.protocols.most_common(10):
            percentage = (count / len(self.packets)) * 100
            print(f"{protocol:12} {count:6} packets ({percentage:5.1f}%)")

        print(f"\n📤 TOP SOURCE IPs")
        for ip, count in self.src_ips.most_common(10):
            percentage = (count / len(self.packets)) * 100
            print(f"{ip:15} {count:6} packets ({percentage:5.1f}%)")

        print(f"\n📥 TOP DESTINATION IPs")
        for ip, count in self.dst_ips.most_common(10):
            percentage = (count / len(self.packets)) * 100
            print(f"{ip:15} {count:6} packets ({percentage:5.1f}%)")

        print(f"\n🔌 TOP PORTS")
        for port, count in self.ports.most_common(10):
            percentage = (count / len(self.packets)) * 100
            print(f"{port:12} {count:6} packets ({percentage:5.1f}%)")

        if self.tcp_flags:
            print(f"\n🚩 TCP FLAGS")
            for flag, count in self.tcp_flags.most_common():
                print(f"{flag:8} {count:6} packets")

    def create_visualizations(self):
        """Create various network traffic visualizations"""
        plt.style.use('default')
        fig = plt.figure(figsize=(20, 15))

        # 1. Protocol Distribution Pie Chart
        plt.subplot(3, 3, 1)
        top_protocols = dict(self.protocols.most_common(8))
        others_count = sum(self.protocols.values()) - sum(top_protocols.values())
        if others_count > 0:
            top_protocols['Others'] = others_count

        colors = plt.cm.Set3(np.linspace(0, 1, len(top_protocols)))
        plt.pie(top_protocols.values(), labels=top_protocols.keys(), autopct='%1.1f%%', colors=colors)
        plt.title('Protocol Distribution', fontsize=14, fontweight='bold')

        # 2. Packet Size Distribution
        plt.subplot(3, 3, 2)
        plt.hist(self.packet_sizes, bins=50, alpha=0.7, color='skyblue', edgecolor='black')
        plt.xlabel('Packet Size (bytes)')
        plt.ylabel('Frequency')
        plt.title('Packet Size Distribution', fontsize=14, fontweight='bold')
        plt.grid(True, alpha=0.3)

        # 3. Top Source IPs
        plt.subplot(3, 3, 3)
        top_src_ips = dict(self.src_ips.most_common(10))
        plt.barh(list(top_src_ips.keys()), list(top_src_ips.values()), color='lightcoral')
        plt.xlabel('Packet Count')
        plt.title('Top Source IP Addresses', fontsize=14, fontweight='bold')
        plt.gca().invert_yaxis()

        # 4. Top Destination IPs
        plt.subplot(3, 3, 4)
        top_dst_ips = dict(self.dst_ips.most_common(10))
        plt.barh(list(top_dst_ips.keys()), list(top_dst_ips.values()), color='lightgreen')
        plt.xlabel('Packet Count')
        plt.title('Top Destination IP Addresses', fontsize=14, fontweight='bold')
        plt.gca().invert_yaxis()

        # 5. Traffic Over Time
        plt.subplot(3, 3, 5)
        if len(self.timestamps) > 1:
            # Create time bins
            time_diff = (self.timestamps[-1] - self.timestamps[0]).total_seconds()
            bins = min(50, int(time_diff))
            plt.hist([t.timestamp() for t in self.timestamps], bins=bins, alpha=0.7, color='purple')
            plt.xlabel('Time')
            plt.ylabel('Packets per Time Bin')
            plt.title('Traffic Over Time', fontsize=14, fontweight='bold')
            plt.xticks(rotation=45)

        # 6. Top Ports
        plt.subplot(3, 3, 6)
        top_ports = dict(self.ports.most_common(10))
        if top_ports:
            plt.bar(range(len(top_ports)), list(top_ports.values()), color='orange')
            plt.xlabel('Ports')
            plt.ylabel('Packet Count')
            plt.title('Top Ports Activity', fontsize=14, fontweight='bold')
            plt.xticks(range(len(top_ports)), list(top_ports.keys()), rotation=45)

        # 7. TCP Flags Distribution
        plt.subplot(3, 3, 7)
        if self.tcp_flags:
            plt.bar(self.tcp_flags.keys(), self.tcp_flags.values(), color='red', alpha=0.7)
            plt.xlabel('TCP Flags')
            plt.ylabel('Count')
            plt.title('TCP Flags Distribution', fontsize=14, fontweight='bold')

        # 8. Packet Size Box Plot
        plt.subplot(3, 3, 8)
        plt.boxplot(self.packet_sizes, patch_artist=True,
                    boxprops=dict(facecolor='lightblue', alpha=0.7))
        plt.ylabel('Packet Size (bytes)')
        plt.title('Packet Size Statistics', fontsize=14, fontweight='bold')
        plt.grid(True, alpha=0.3)

        # 9. Network Activity Heatmap (if enough data)
        plt.subplot(3, 3, 9)
        try:
            # Create hour-based activity heatmap
            hours = [t.hour for t in self.timestamps]
            days = [t.weekday() for t in self.timestamps]

            # Create a matrix for the heatmap
            activity_matrix = np.zeros((7, 24))
            for day, hour in zip(days, hours):
                activity_matrix[day, hour] += 1

            day_names = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
            sns.heatmap(activity_matrix,
                        xticklabels=range(24),
                        yticklabels=day_names,
                        cmap='YlOrRd',
                        annot=False,
                        cbar_kws={'label': 'Packet Count'})
            plt.title('Network Activity Heatmap', fontsize=14, fontweight='bold')
            plt.xlabel('Hour of Day')
            plt.ylabel('Day of Week')
        except:
            plt.text(0.5, 0.5, 'Insufficient data\nfor heatmap',
                     ha='center', va='center', transform=plt.gca().transAxes)
            plt.title('Network Activity Heatmap', fontsize=14, fontweight='bold')

        plt.tight_layout()

        # Save the plot
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"network_analysis_{timestamp}.png"
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        print(f"\n📈 Visualizations saved as: {filename}")

        # Try to show plot, but don't fail if GUI is unavailable
        try:
            plt.show()
        except:
            print("📊 Graph display unavailable - check the saved PNG file instead")

    def export_data(self):
        """Export analyzed data to CSV files"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Protocol data
        protocol_df = pd.DataFrame(list(self.protocols.items()),
                                   columns=['Protocol', 'Count'])
        protocol_df.to_csv(f'protocols_{timestamp}.csv', index=False)

        # IP data
        ip_df = pd.DataFrame({
            'Source_IP': list(self.src_ips.keys()),
            'Source_Count': list(self.src_ips.values())
        })
        ip_df.to_csv(f'source_ips_{timestamp}.csv', index=False)

        # Port data
        port_df = pd.DataFrame(list(self.ports.items()),
                               columns=['Port', 'Count'])
        port_df.to_csv(f'ports_{timestamp}.csv', index=False)

        print(f"📄 Data exported to CSV files with timestamp: {timestamp}")


def main():
    parser = argparse.ArgumentParser(description='Network Traffic Analyzer')
    parser.add_argument('-i', '--interface', help='Network interface to capture from')
    parser.add_argument('-f', '--file', help='PCAP file to analyze')
    parser.add_argument('-c', '--count', type=int, default=1000,
                        help='Number of packets to capture (default: 1000)')
    parser.add_argument('--no-gui', action='store_true',
                        help='Run without showing graphs')
    parser.add_argument('--export', action='store_true',
                        help='Export data to CSV files')

    args = parser.parse_args()

    if not args.interface and not args.file:
        print("Error: Must specify either interface (-i) or pcap file (-f)")
        print("\nAvailable interfaces:")
        try:
            import psutil
            for interface, addrs in psutil.net_if_addrs().items():
                print(f"  - {interface}")
        except:
            print("  Install psutil to see available interfaces: pip install psutil")
        sys.exit(1)

    # Create analyzer instance
    analyzer = NetworkTrafficAnalyzer(
        interface=args.interface,
        pcap_file=args.file,
        packet_count=args.count
    )

    # Capture and analyze packets
    analyzer.capture_packets()

    # Generate statistics
    analyzer.generate_statistics()

    # Create visualizations
    if not args.no_gui:
        analyzer.create_visualizations()

    # Export data if requested
    if args.export:
        analyzer.export_data()


if __name__ == "__main__":
    main()