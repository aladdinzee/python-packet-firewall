import json
import logging
from scapy.all import sniff,IP,TCP

with open('rules.json') as f:
    rules = json.load(f)

BLOCKED_IP = rules.get("blocked_ips",[]) 
BLOCKED_PORTS = rules.get("blocked_ports",[])

logging.basicConfig(filename = "firewall.log",level = logging.INFO)

def process_packet(packet):
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        if src_ip in BLOCKED_IP or dst_port in BLOCKED_PORTS:
            log_msg = f"Blocked packet from {src_ip} to destination port {dst_port}"
            print(log_msg)
            logging.info(log_msg)
        else:
            log_msg = f"Allowed packet from {src_ip} to destination port {dst_port}"
            print(log_msg)
            logging.info(log_msg)

sniff(prn=process_packet, store = False, timeout = 180)