# NetworkTrafficAnalyzer

A Python tool to analyze network traffic using Wireshark's `tshark` engine (via PyShark). It generates insightful statistics and visualizations.

## Features

- Captures live traffic or reads from a `.pcap` file
- Detects and displays protocol distribution, top IPs, ports, TCP flags
- Creates detailed matplotlib-based visualizations
- Exports data to CSV format

## Dependencies

Install required libraries:

```bash
pip install pyshark matplotlib seaborn pandas numpy psutil
