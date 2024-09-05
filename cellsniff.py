from scapy.all import *
from scapy.layers.dot11 import Dot11, RadioTap
import signal
import sys

KNOWN_IP = "192.168.4.4"  # Replace with the actual known IP
iface = "wlan1"  # Your interface must be in monitor mode

# List to store captured RSSI values
rssi_values = []

def get_rssi(packet):
    """Extract RSSI from Radiotap header"""
    if packet.haslayer(RadioTap):
        rssi = -(256 - ord(packet.notdecoded[-4:-3]))  # Extract RSSI from the Radiotap layer
        return rssi
    return None

def process_packet(packet):
    """Process each packet to filter ICMP Echo Requests and capture RSSI"""
    if packet.haslayer(Dot11):
        # Check if it has a payload and if we can decode it to IP
        if packet.type == 2:  # Data frame
            raw_packet = packet[Dot11].payload
            if raw_packet.haslayer(IP):
                ip_layer = raw_packet.getlayer(IP)
                icmp_layer = raw_packet.getlayer(ICMP)

                # Check if it's an ICMP Echo Request (ping)
                if icmp_layer.type == 8 and ip_layer.src == KNOWN_IP:
                    rssi = get_rssi(packet)
                    if rssi is not None:
                        print(f"ICMP Echo Request from {ip_layer.src} | RSSI: {rssi} dBm")
                        rssi_values.append(rssi)
                    else:
                        print(f"ICMP Echo Request from {ip_layer.src} | RSSI: Not available")

def calculate_average_rssi():
    """Calculate and display the average RSSI when the program is terminated"""
    if rssi_values:
        average_rssi = sum(rssi_values) / len(rssi_values)
        print(f"\nAverage RSSI: {average_rssi:.2f} dBm")
    else:
        print("\nNo RSSI values captured.")

def signal_handler(sig, frame):
    """Handle program termination and display average RSSI"""
    print("\nTerminating program...")
    calculate_average_rssi()
    sys.exit(0)

# Attach the signal handler to handle Ctrl+C (SIGINT)
signal.signal(signal.SIGINT, signal_handler)

# Start sniffing on the wireless interface in monitor mode
print(f"Sniffing on {iface}, waiting for ICMP Echo Requests from {KNOWN_IP}...")
sniff(iface=iface, prn=process_packet, store=0)
