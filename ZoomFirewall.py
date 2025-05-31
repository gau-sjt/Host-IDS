#!/usr/bin/env python3

"""
Real-Time Firewall using Machine Learning (Windows)

- Captures live packets using Scapy
- Extracts features expected by the model
- Predicts whether the traffic is normal or attack
- Blocks malicious IP addresses using Windows Defender Firewall

Author: You (for Internet Cafe Deployment)
"""

import subprocess
import pandas as pd
import joblib
from scapy.all import sniff, TCP, IP, UDP, ICMP
import time

# ====== SETTINGS ======
MODEL_PATH = "C:\\Path\\To\\HostIDS.joblib"  # <-- Update this for Windows path
INTERFACE = None  # Set to None for auto-select, or use "Wi-Fi" / "Ethernet"
# =======================

# Load the trained firewall model
print(f"Loading model from {MODEL_PATH}...")
model = joblib.load(MODEL_PATH)
print("Model loaded successfully.")

# Services mapping
def infer_service(port):
    common_ports = {
        80: 'http',
        443: 'https',
        22: 'ssh',
        21: 'ftp',
        25: 'smtp',
        110: 'pop3',
        143: 'imap4',
        23: 'telnet',
        53: 'domain',
        123: 'ntp_u',
        20: 'ftp_data'
    }
    return common_ports.get(port, 'other')

# Feature extraction from a live packet
def extract_features(pkt):
    if IP in pkt:
        proto = pkt.proto
        if TCP in pkt:
            layer = pkt[TCP]
            sport = layer.sport
            flags = layer.flags

            flag = "SF" if flags == 0x12 else "S0" if flags == 0x2 else "REJ" if flags == 0x14 else "OTH"

            return {
                'Sport': sport,
                'service': infer_service(layer.dport),
                'flag': flag,
                'protocol_type': 'tcp'
            }
        elif UDP in pkt:
            layer = pkt[UDP]
            sport = layer.sport
            return {
                'Sport': sport,
                'service': infer_service(layer.dport),
                'flag': 'OTH',
                'protocol_type': 'udp'
            }
        elif ICMP in pkt:
            return {
                'Sport': 0,
                'service': 'eco_i',
                'flag': 'OTH',
                'protocol_type': 'icmp'
            }
    return None

# Windows-specific IP blocker
def block_ip(ip_address):
    try:
        print(f"Blocking IP {ip_address} on Windows Firewall...")
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name=Block_{ip_address}",
            "dir=in",
            "action=block",
            f"remoteip={ip_address}"
        ], check=True)
        print(f"IP {ip_address} blocked successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error blocking IP {ip_address}: {e}")

# Main handler for each captured packet
def handle_packet(pkt):
    features = extract_features(pkt)
    if features:
        df = pd.DataFrame([features])

        for col in model.named_steps['pre'].feature_names_in_:
            if col not in df.columns:
                df[col] = 0

        prediction = model.predict(df)[0]

        if prediction == 1:
            src_ip = pkt[IP].src
            print(f"ALERT: Attack detected from {src_ip}!")
            block_ip(src_ip)

# Start sniffing live traffic
def start_firewall():
    print("Real-Time Firewall Started (Windows Version). Monitoring traffic...")
    print("Press Ctrl+C to stop.")

    sniff(prn=handle_packet, store=0, iface=INTERFACE)

if __name__ == "__main__":
    start_firewall()
