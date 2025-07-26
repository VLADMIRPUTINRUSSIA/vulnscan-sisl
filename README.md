# VULNSCAN-SISL

## Overview

VULNSCAN-SISL is an all-in-one, terminal-based vulnerability and surveillance detection scanner designed to identify leaked government cyber tools and implants such as EternalBlue, EternalRomance, Heartbleed, Weeping Angel, Brutal Kangaroo, and more. It also detects possible monitoring or surveillance of your device and network traffic.

The tool is intended for authorized security research, red-team operations, and educational purposes only.

---

## Features

- Detects multiple leaked NSA, CIA, FBI cyber exploits and implants.
- Performs OS fingerprinting using `nmap`.
- Analyzes network traffic for signs of surveillance or monitoring.
- Logs output in JSON and CSV formats.
- Supports Discord webhook integration for real-time alerting.
- Auto-updates detection signatures.
- Compatible with Debian-based Linux (Ubuntu, Kali, Debian).

---

## Requirements

### System Dependencies

- Python 3.7+
- pip3 (Python package installer)
- nmap (network scanner and OS fingerprinting)
- tcpdump (network traffic capture)

### Python Modules

- requests

### Installing Dependencies on Debian/Ubuntu

```bash
sudo apt update
sudo apt install -y python3 python3-pip nmap tcpdump
pip3 install requests
Clone or download the repository:
git clone https://github.com/VLADMIRPUTINRUSSIA/vulnscan-sisl.git
cd vulnscan-sisl
```
## How to Use
Run the tool using Python3:
python3 vulnscan-sisl.py -t <target_ip_or_network> [options]
Required Argument -t --target : Specify target IP address or network range (CIDR) to scan.
```bash
Optional Arguments
Option	Description	Example
--json	Save scan results to a JSON file	--json
--csv	Save scan results to a CSV file	--csv
--webhook	Discord webhook URL for sending alerts	--webhook https://discord.com/api/webhooks/XXXX/XXXX
--update	Force update detection signatures from GitHub	--update
-h, --help	Display help and usage information	-h
Output
JSON output files saved as scan_results_<target>_<timestamp>.json

CSV output files saved as scan_results_<target>_<timestamp>.csv

Logs are stored in the tool directory.
```
# Legal Disclaimer
Use this tool only on networks and systems you own or have explicit permission to test.

Unauthorized scanning may be illegal in your jurisdiction.

The tool cannot guarantee detection of all surveillance or advanced persistent threats.

The developers disclaim all liability for misuse or damages.
# License
This project is licensed under the MIT License. See the LICENSE file for full terms.
# Support
For bug reports, feature requests, or questions, please open an issue on GitHub.
# Contact
Developed and maintained by SISL Intelligence Lab
Secured By SISL Int Lab

