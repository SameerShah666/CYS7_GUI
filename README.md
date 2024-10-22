# CYS7 Sniffing & Scanning Application

## Overview

The **CYS7 Sniffing & Scanning Application** is a network analysis tool built using Python. It allows users to sniff network packets, perform port scans, and manage sniffed packet data. The application features a user-friendly GUI created with the `CustomTkinter` library and leverages `Scapy` for network packet manipulation.

## Features

- **Packet Sniffing**: Capture packets based on user-defined filters (e.g., TCP, UDP).
- **Port Scanning**: Scan specified ports on a target IP to check their status (open, closed, or filtered).
- **Save & Load Packets**: Save sniffed packets to a PCAP file and load packets from existing PCAP files for analysis.
- **User-Friendly Interface**: Dark theme and organized layout for easy navigation.

## Requirements

To run this application, you need the following Python packages:

- `CustomTkinter`
- `Scapy`

You can install the required packages using pip:

```bash
pip install customtkinter scapy
```
### Acknowledgement
This project is inspired from [CYS7](https://github.com/JAS-JPG/Packet-Sniffer-For-MiTM) which was a group project with collaborators [SameerShah666](https://github.com/SameerShah666) & [JAS-JPG](https://github.com/JAS-JPG)