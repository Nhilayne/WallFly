import socket
import struct
import os

# Replace with your known IP address
KNOWN_IP = "192.168.4.16"  # Example IP address

# Initialize variables to store RSSI values and count
rssi_values = []
packet_count = 0

def get_rssi_from_packet(packet):
    # Extract RSSI from packet (needs specific implementation based on your environment)
    # Placeholder implementation; adjust according to your setup
    return -50  # Example RSSI value; replace with actual extraction logic

def process_packet(packet):
    global rssi_values, packet_count
    
    # Unpack IP header
    ip_header = packet[:20]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    protocol = iph[6]
    src_ip = socket.inet_ntoa(iph[8])
    
    # Check if the packet is ICMP and from the known IP
    if protocol == 1:  # ICMP
        # Extract ICMP header (start after IP header)
        icmp_header = packet[20:28]
        icmp_type, = struct.unpack('!BB', icmp_header[:2])
        
        if icmp_type == 8 and src_ip == KNOWN_IP:  # Type 8 is Echo Request
            # Extract RSSI
            rssi = get_rssi_from_packet(packet)
            rssi_values.append(rssi)
            packet_count += 1

def main():
    global rssi_values, packet_count
    
    # Create a raw socket to capture ICMP packets
    try:
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print("Permission denied. You need to run this script with root privileges.")
        return
    
    # Bind the socket to all interfaces
    raw_socket.bind(('0.0.0.0', 0))
    
    print("Starting packet sniffing. Press Ctrl+C to stop.")
    
    try:
        while True:
            packet = raw_socket.recvfrom(65565)[0]  # Receive packets
            process_packet(packet)
    except KeyboardInterrupt:
        print("Stopping packet sniffing.")
    
    # Calculate and display average RSSI
    if packet_count > 0:
        average_rssi = sum(rssi_values) / len(rssi_values)
        print(f"Average RSSI from {KNOWN_IP}: {average_rssi} dBm")
    else:
        print(f"No ICMP Echo Requests found from {KNOWN_IP}")

if __name__ == "__main__":
    main()