import socket
import argparse
import select
import math
import time
import struct
from scapy.all import *
import uuid
import threading
import subprocess
import datetime
import ntplib
from time import ctime, sleep
import os


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", "-i", default="wlan1", help="Network Monitoring Interface")
    parser.add_argument("--server", "-s", help="Processing Server IP")
    parser.add_argument("--port", "-p", default=8505, help="Processing Server Port")
    parser.add_argument("--location", "-l", default="0,0,0", help="")
    parser.add_argument("--channels","-c", default="1,6,11", help="Wireless channels to monitor")
    return parser.parse_args()

def init_connection(server, port):
    connection = socket.socket()
    connection.connect((server, int(port)))
    return connection

def get_mac_address():
    id = uuid.getnode()
    id_formatted = ':'.join(('%012x'%id)[i:i+2] for i in range(0,12,2))
    return id_formatted.lower()

def parse_packet(pkt):
    if not pkt.haslayer(Dot11):
        return None
    if pkt.type == 0 and pkt.subtype == 4:
        mac_addr = pkt.addr2
        mac_addr = mac_addr.upper()
        rssi = pkt.dBm_AntSignal
        # devices.add(mac_addr)
        # print(pkt)
        data = (f'{mac_addr}|{rssi}|{pkt.time}')
        for key, value in networkStrength.items():
            # print(f'checking {mac_addr} against listed {key}')
            if mac_addr.upper() == key.upper():
                networkStrength[key] = rssi
                print(f'updated {key} to {rssi}')
                return
            data += (f'|{value}')
        # print(data)
        return data

def create_probe_request(ssid, id):
    # Generate a random MAC address for the source (optional)
    # src_mac = ':'.join([f'{random.randint(0x00, 0xFF):02x}' for _ in range(6)])
    srcMAC = id

    # Probe request frame creation
    probe_request = RadioTap() / \
                    Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff", addr2=srcMAC, addr3="ff:ff:ff:ff:ff:ff") / \
                    Dot11ProbeReq() / \
                    Dot11Elt(ID=0, info=ssid) / \
                    Dot11Elt(ID=1, info=b'\x02\x04\x0b\x16') / \
                    Dot11Elt(ID=3, info=chr(1)) / \
                    Dot11Elt(ID=50, info=b'\x0c\x12\x18\x24')

    # Send the probe request
    # sendp(probe_request, iface=interface, count=1, inter=0.1, verbose=1)

    return probe_request

def close():
    pass

#channel sync
####
def synchronized_start():
    currentTime = datetime.datetime.now()
    timeToWait = 1.0 - (currentTime.microsecond / 1000000.0)
    time.sleep(timeToWait)

def channel_hopper(interface, channels, interval):
    print(f'interface {interface} hopping channels {channels} every {interval} seconds')
    while True:
        for channel in channels:
            subprocess.call(['iwconfig',interface,'channel',channel])
            time.sleep(interval)

def channel_set(interface, channel):
    subprocess.call(['iwconfig',interface,'channel',channel])
    print(f'interface {interface} set to channel {channel}')

def sync_ntp_time(ntpServer='192.168.4.1'):
    ntpClient = ntplib.NTPClient()
    try:
        response = ntpClient.request(ntpServer, version=3)
        currentTime = ctime(response.tx_time)
        print(f'NTP Time: {currentTime}')

        os.system(f'sudo chronyc makestep')
        print(f'systemtime sync\'d to ntp server')
    except Exception as e:
        print(f'failed to sync time: {e}')

#sniffing
####
def capture_packets(interface, queue):
    def packet_handler(packet):
        queue.put(packet)
    
    sniff(iface=interface, prn=packet_handler, timeout=None)


def main():

    args = get_args()
    
    clientID = get_mac_address()

    #Force sync to ntp server
    ####
    sync_ntp_time(args.server)
    ####

    conn = init_connection(args.server,args.port)
    
    initMsg = f'init|{clientID}|{args.location}'

    conn.send(initMsg.encode())

    global send_buffer
    send_buffer = queue.Queue()

    global networkStrength
    networkStrength = {clientID:0}

    environmentBaselineTimer = 0
    
    

    #sniffing interface channel parameters
    ####
    channels = args.channels.split(',')
    channelHopInterval = 0.5 
    ####
    #start sync'd channel hopping in separate thread if multiple
    #wait for server start signal
    print('Waiting for server start signal')
    conn.recv(1024)
    print('syncing Start')
    synchronized_start()
    
    if len(channels) == 1:
        channel_set(args.interface, channels[0])
    else:
        hopperThread = threading.Thread(target=channel_hopper, args=(args.interface, channels, channelHopInterval))
        hopperThread.deamon = True
        hopperThread.start()

    sniffingThread = threading.Thread(target=capture_packets, args=(args.interface, send_buffer))
    sniffingThread.daemon = True
    sniffingThread.start()

    print('starting')
    while True:
        try:
            # sniff(iface=args.interface, prn=handle_packet, timeout=0.01)
            readSockets,_,_ = select.select([conn],[],[],0)
            
            # check for server messages
            for packet in readSockets:
                msg = packet.recv(1028)
                if not msg:
                    print('Server connection closed')
                    conn.close()
                    exit()
                else:
                    data = msg.decode()
                    print(f'recvd {data}')
                    data = data.split('update')
                    for msg in data:
                        if msg =='':
                            continue
                        print(msg)
                        msg = msg.split('|')
                        print(msg[1])
                        networkStrength[msg[1]] = 0
                    # if data[0] == 'update':
                        # position = tuple(float(x) for x in data[2][1:-1].split(','))
                        # print(f'testing::{position[0]}+{position[1]}+{position[2]}')
                        # convertedDistance = round(math.sqrt(position[0]**2+position[1]**2+position[2]**2),3)
                        # print(f'abs dist: {convertedDistance}')
                        # print(data[1])
                        # networkStrength[data[1]] = 0

            # send sniffed data to server and remove from queue
            while not send_buffer.empty():
                pkt = send_buffer.get()
                data = parse_packet(pkt)
                if data:
                    conn.send(data.encode())
            
            # broadcast ping request for other clients to sniff ~10x per second.
            ##########
            # with distance known from server provided blacklist,
            # the current radio environment can be potentially measured 
            # and relayed to server to assist with processing.
            ##########
            environmentBaselineTimer += 1
            if environmentBaselineTimer >= 10000000:
                environmentBaselineTimer = 0
                frame = create_probe_request('WallFly', clientID)
                print("broadcasting probe")
                # sendp(frame, iface=interface, count=1, inter=0.1, verbose=0)
                sendp(frame, iface=args.interface, verbose=False)

        except KeyboardInterrupt:
            conn.close()
            exit()
    

if __name__ == '__main__':
    main()