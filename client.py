import socket
import argparse
import select
import time
import struct
from scapy.all import sniff, Dot11
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
    global send_buffer
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

    args = get_args()
    
    clientID = get_mac_address()

   
    conn = init_connection(args.server,args.port)
    
    initMsg = f'init|{clientID}|{args.location}'

    conn.send(initMsg.encode())

    send_buffer = []
    
    while True:
        try:
            sniff(iface=args.interface, prn=handle_packet, timeout=0.01)
            readSockets,_,_ = select.select([conn],[],[],0)
            for packet in readSockets:
                msg = packet.recv(1028)
                if not msg:
                    print('connection closed')
                    conn.close()
                    exit()
                else:
                    data = msg.decode()
                    print(f'recvd {data}')
                    
            for data in send_buffer:
                conn.send(data.encode())
                send_buffer.remove(data)

        except KeyboardInterrupt:
            conn.close()
            exit()
    

if __name__ == '__main__':
    main()