import socket
import argparse
import select
import time
import struct
from scapy.all import sniff, Dot11

devices = set()
send_buffer = []

def handle_packet(pkt):
    if not pkt.haslayer(Dot11):
        return None
    if pkt.type == 0 and pkt.subtype == 4:
        mac_addr = pkt.addr2
        mac_addr = mac_addr.upper()
        rssi = pkt.dBm_AntSignal
        # devices.add(mac_addr)
        # print(pkt)
        data = (f'{mac_addr}|{rssi}|{pkt.time}')
        # print(data)
        send_buffer.append(data)

def close():
    pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", "-i", default="wlan1", help="Network Monitoring Interface")
    parser.add_argument("--server", "-s", help="Processing Server IP")
    parser.add_argument("--port", "-p", default=8505, help="Processing Server Port")
    args = parser.parse_args()
    
    conn = socket.socket()
    conn.connect((args.server, int(args.port)))
    
    while True:
        try:
            sniff(iface=args.interface, prn=handle_packet, timeout=0.01)

            for data in send_buffer:
                conn.send(data.encode())
                send_buffer.remove(data)

        except KeyboardInterrupt:
            conn.close()
            exit()
    

if __name__ == '__main__':
    main()