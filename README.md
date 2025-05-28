# python-packet-firewall

# 🛡️ Python Packet Filtering Firewall

This is aPython-based packet sniffing firewall that captures, filters, and logs network packets using the [Scapy](https://scapy.readthedocs.io/) library.

The Firewall script allows the users to define blocked IP addresses and ports through a simple configuration file (rules.json). As the firewall runs, it prints and logs any packet that matches the block rules, making it easy to observe potentially malicious or unwanted traffic. The script runs for a predefined period (default: 5 minutes) and is built with clarity and modularity in mind.

While it doesn't actively block packets at the OS level, this project serves as a foundational step toward understanding packet-level inspection, firewall logic, and intrusion detection concepts. Further enahancements on this project is ongoing.

---

## 🔍 Features

- ✅ Real-time packet sniffing using Scapy
- ✅ Block packets by IP addresses and/or TCP ports
- ✅ Logs blocked traffic to `firewall.log`
- ✅ Runs for a defined duration (default: 5 minutes)
- ✅ Easily configurable via `rules.json`

---

## 📁 Project Structure

|----- script.py #Main script
|----- firewall.log #Auto-generated log of blocked packets
|----- rules.json #IP and Port filtering rules
|----- LICENSE #MIT Liecnse for Copyrights

