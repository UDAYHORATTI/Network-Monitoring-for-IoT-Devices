# Network-Monitoring-for-IoT-Devices
This script monitors network traffic for IoT devices, logs details of the packets they send or receive, and checks for any unusual activity (e.g., excessive data transfer, unexpected ports, etc.).
import scapy.all as scapy
import time
import logging
from collections import defaultdict
import re

# Configuration
NETWORK_INTERFACE = "eth0"  # Network interface for monitoring (use 'wlan0' for WiFi)
LOG_FILE = "iot_traffic.log"  # Log file for storing IoT traffic details
ANOMALY_THRESHOLD = 1000000  # Anomaly threshold in bytes (1MB), above which the device is flagged
CHECK_INTERVAL = 60  # Time interval to check network usage (in seconds)

# Setting up logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(message)s')

# Dictionary to store IoT devices usage
iot_devices_usage = defaultdict(lambda: {'bytes_in': 0, 'bytes_out': 0, 'last_activity': time.time(), 'flagged': False})

# Function to log traffic details of IoT devices
def log_traffic(ip, direction, packet_size):
    if direction == "in":
        iot_devices_usage[ip]['bytes_in'] += packet_size
    elif direction == "out":
        iot_devices_usage[ip]['bytes_out'] += packet_size
    iot_devices_usage[ip]['last_activity'] = time.time()
    logging.info(f"IP: {ip}, Direction: {direction}, Size: {packet_size} bytes")

# Function to detect anomalies (e.g., unusual data transfer)
def detect_anomalies(ip, usage):
    total_usage = usage['bytes_in'] + usage['bytes_out']
    if total_usage > ANOMALY_THRESHOLD and not usage['flagged']:
        iot_devices_usage[ip]['flagged'] = True
        logging.warning(f"Anomaly detected for IP {ip}: Data usage exceeded threshold of {ANOMALY_THRESHOLD} bytes")
        print(f"ALERT: Device {ip} is flagged for excessive data usage!")

# Function to handle each packet and monitor IoT devices
def packet_handler(packet):
    try:
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dest_ip = packet[scapy.IP].dst
            packet_size = len(packet)

            # Log incoming traffic for the destination device (IoT device)
            if packet[scapy.IP].dst == dest_ip:
                log_traffic(dest_ip, "in", packet_size)

            # Log outgoing traffic for the source device (IoT device)
            if packet[scapy.IP].src == src_ip:
                log_traffic(src_ip, "out", packet_size)

            # Detect anomalies in IoT devices' traffic
            detect_anomalies(src_ip, iot_devices_usage[src_ip])
            detect_anomalies(dest_ip, iot_devices_usage[dest_ip])

    except Exception as e:
        logging.error(f"Error processing packet: {e}")

# Function to display IoT device usage summary
def display_usage():
    print("IoT Device Network Usage Summary:")
    print("-" * 50)
    for ip, usage in iot_devices_usage.items():
        total_usage = usage['bytes_in'] + usage['bytes_out']
        print(f"IP Address: {ip}")
        print(f"  - Incoming Traffic: {usage['bytes_in'] / (1024 * 1024):.2f} MB")
        print(f"  - Outgoing Traffic: {usage['bytes_out'] / (1024 * 1024):.2f} MB")
        print(f"  - Total Traffic: {total_usage / (1024 * 1024):.2f} MB")
        if usage['flagged']:
            print(f"  - Status: FLAGGED (Anomaly detected)")
        else:
            print(f"  - Status: OK")
        print("-" * 50)

# Function to start the packet sniffing process
def start_sniffing():
    print("Starting IoT device network monitoring...")
    scapy.sniff(iface=NETWORK_INTERFACE, prn=packet_handler, store=0)

# Function to periodically check and display the traffic summary
def run_monitoring():
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()

    while True:
        time.sleep(CHECK_INTERVAL)
        display_usage()

# Main execution
if __name__ == "__main__":
    run_monitoring()
