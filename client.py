import socket
import argparse
import select
import math
import time
import struct
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt, RadioTap, RandMAC, sendp
import uuid

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", "-i", default="wlan1", help="Network Monitoring Interface")
    parser.add_argument("--server", "-s", help="Processing Server IP")
    parser.add_argument("--port", "-p", default=8505, help="Processing Server Port")
    parser.add_argument("--location", "-l", default="0,0,0", help="")
    return parser.parse_args()

def init_connection(server, port):
    connection = socket.socket()
    connection.connect((server, int(port)))
    return connection

def get_mac_address():
    id = uuid.getnode()
    id_formatted = ':'.join(('%012x'%id)[i:i+2] for i in range(1,12,2))
    return id_formatted.lower()

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

def create_ping_request():
    # Crafting a Dot11 packet
    dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=RandMAC(), addr3=RandMAC())
    beacon = Dot11Beacon(cap='ESS+privacy')
    essid = Dot11Elt(ID='SSID', info='TestNetwork', len=10)
    rsn = Dot11Elt(ID='RSNinfo', info=(
        '\x01\x00'                 # RSN Version 1
        '\x00\x0f\xac\x02'         # Group Cipher Suite (TKIP)
        '\x02\x00'                 # 2 Pairwise Cipher Suites (unicast)
        '\x00\x0f\xac\x04'         # AES Cipher
        '\x00\x0f\xac\x02'         # TKIP Cipher
        '\x01\x00'                 # 1 Authentication Key Management Suite (802.1X)
        '\x00\x0f\xac\x02'         # Pre-Shared Key
        '\x00\x00'))               # RSN Capabilities (no extra capabilities)

    # Combine the Dot11, Beacon, and SSID elements
    frame = RadioTap()/dot11/beacon/essid/rsn

    return frame

def close():
    pass

def main():

    args = get_args()
    
    clientID = get_mac_address()

   
    conn = init_connection(args.server,args.port)
    
    initMsg = f'init|{clientID}|{args.location}'

    conn.send(initMsg.encode())

    global send_buffer
    send_buffer = []
    
    networkBlacklist = {clientID:(args.location)}
    environmentBaselineTimer = 0
    environmentBaselineMonitor = {}
    while True:
        try:
            sniff(iface=args.interface, prn=handle_packet, timeout=0.01)
            readSockets,_,_ = select.select([conn],[],[],0)
            
            # check for server messages
            for packet in readSockets:
                msg = packet.recv(1028)
                if not msg:
                    print('connection closed')
                    conn.close()
                    exit()
                else:
                    data = msg.decode()
                    print(f'recvd {data}')
                    data = data.split("|")
                    if data[0] == 'update':
                        position = tuple(float(x) for x in data[2][1:-1].split(','))
                        print(f'testing::{position[0]}+{position[1]}+{position[2]}')
                        convertedDistance = round(math.sqrt(position[0]**2+position[1]**2+position[2]**2),3)
                        print(f'abs dist: {convertedDistance}')
                        networkBlacklist[data[1]] = convertedDistance

            # send sniffed data to server and remove from queue
            for data in send_buffer:
                conn.send(data.encode())
                send_buffer.remove(data)
            
            # broadcast ping request for other clients to sniff 10x per second.
            ##########
            # with distance known from server provided blacklist,
            # the current radio environment can be potentially measured 
            # and relayed to server to assist with processing.
            ##########
            environmentBaselineTimer += 1
            if environmentBaselineTimer >= 10:
                environmentBaselineTimer = 0
                frame = create_ping_request()
                print("broadcast sending")
                sendp(frame, iface=args.interface, verbose=False)

        except KeyboardInterrupt:
            conn.close()
            exit()
    

if __name__ == '__main__':
    main()