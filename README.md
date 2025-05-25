# Network Traffic Analyzer

Network Traffic Analyzer is a Python-based utility designed for capturing and analyzing network traffic either from a live interface or a `.pcap` file using `pyshark` (a Python wrapper for tshark/Wireshark). The tool generates insightful statistics and a range of visualizations to help understand traffic patterns, protocol usage, and network behavior.

---

## Features

- Capture live network traffic from a specified interface
- Analyze `.pcap` files offline
- Summarize:
  - Protocol usage
  - Source/Destination IP addresses
  - TCP/UDP ports
  - TCP flag distribution
  - Packet size statistics
- Generate visualizations including:
  - Protocol distribution pie chart
  - Packet size histogram and boxplot
  - Top IPs and ports bar charts
  - Traffic heatmap by day/hour
- Export analysis results to CSV files
- Save visualizations as high-resolution PNG files

---

## Requirements

The following Python packages are required:

- `pyshark`
- `matplotlib`
- `seaborn`
- `pandas`
- `numpy`
- `argparse`
- `psutil` *(optional, for listing available interfaces)*

To install dependencies, run:

```bash
pip install -r requirements.txt

