import socket
import argparse
import select
import math
import time
from scapy.all import *
import uuid
import threading
import subprocess
import datetime
import ntplib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("ptValue", help="Calibrated PT value")
    parser.add_argument("nValue", help="Calibrated N value")
    parser.add_argument("--interface", "-i", default="wlan1", help="Network Monitoring Interface")
    parser.add_argument("--server", "-s", default='192.168.4.1', help="Processing Server IP")
    parser.add_argument("--port", "-p", default=8505, help="Processing Server Port")
    parser.add_argument("--location", "-l", default="0,0,0", help="Location vector")
    parser.add_argument("--channels","-c", default="1,6,11", help="Wireless channels to monitor")
    parser.add_argument("--knownMAC", "-mac", default=None, help="Sniff only for specified MAC, for use with server location mode")
    return parser.parse_args()

def init_connection(server, port):
    connection = socket.socket()
    connection.connect((server, int(port)))
    return connection

def get_mac_address():
    id = uuid.getnode()
    id_formatted = ':'.join(('%012x'%id)[i:i+2] for i in range(0,12,2))
    return id_formatted.lower()

def get_distance_to_client(remotePosition, localPosition):
    position = [0,0,0]
    position[0] = remotePosition[0] - localPosition[0]
    position[1] = remotePosition[1] - localPosition[1]
    position[2] = remotePosition[2] - localPosition[2]
    distance = round(math.sqrt(position[0]**2 + position[1]**2 + position[2]**2),3)
    return distance

def parse_packet(pkt, filter, pt, n,location):
    if not pkt.haslayer(Dot11):
        return None
    if pkt.type == 0 and pkt.subtype == 4:
        
        mac_addr = pkt.addr2
        mac_addr = mac_addr.upper()
        rssi = pkt.dBm_AntSignal
        if filter and mac_addr.upper() != filter.upper():
            return None
        data = (f'{mac_addr}|{rssi}|{pkt.time}|{pt}|{n}|{location}')
        try:
            for key, value in networkStrength.items():
                if not filter and mac_addr.upper() == key.upper():
                    networkStrength[key][1] = rssi
                    return
        except NameError:
            return data
        return data

def create_probe_request(ssid, id):
    srcMAC = id
    probe_request = RadioTap() / \
                    Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff", addr2=srcMAC, addr3="ff:ff:ff:ff:ff:ff") / \
                    Dot11ProbeReq() / \
                    Dot11Elt(ID=0, info=ssid) / \
                    Dot11Elt(ID=1, info=b'\x02\x04\x0b\x16') / \
                    Dot11Elt(ID=3, info=chr(1)) / \
                    Dot11Elt(ID=50, info=b'\x0c\x12\x18\x24')

    return probe_request

def synchronized_start():
    currentTime = datetime.datetime.now()
    timeToWait = 1.0 - (currentTime.microsecond / 1000000.0)
    time.sleep(timeToWait)

def channel_hopper(interface, channels, interval, max=None):
    print(f'interface {interface} hopping channels {channels} every {interval} seconds')
    iterations = 1
    while True:
        for channel in channels:
            subprocess.call(['iwconfig',interface,'channel',channel])
            time.sleep(interval)
        if max and iterations >= max:
            return
        elif max:
            iterations += 1    

def channel_set(interface, channel):
    subprocess.call(['iwconfig',interface,'channel',channel])
    print(f'interface {interface} set to channel {channel}')

def sync_ntp_time(ntpServer='192.168.4.1'):
    ntpClient = ntplib.NTPClient()
    try:
        response = ntpClient.request(ntpServer, version=3)
        currentTime = time.ctime(response.tx_time)
        print(f'NTP Time: {currentTime}')

        os.system(f'sudo chronyc makestep')
        print(f'systemtime sync\'d to ntp server')
    except Exception as e:
        print(f'failed to sync time: {e}')

def capture_packets(interface, queue, timeout=None):
    def packet_handler(packet):
        queue.put(packet)
    
    sniff(iface=interface, prn=packet_handler, timeout=timeout, store=0)

def encrypt(data, key, iv):
    data += '&'
    data = data.encode('utf-8')
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return base64.b64encode(ciphertext)

def decrypt(data, key, iv):
    ciphertext = base64.b64decode(data)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    if b'&' in decrypted:
        decrypted = decrypted.split(b'&')[0]
    return decrypted.decode()

def main():

    args = get_args()
    
    clientID = get_mac_address()

    aesKey = b'f553692b0eeeb0fc14da46a5a2682616'#32
    aesIV = b'c0dabc32dba054fe'#16

    sync_ntp_time(args.server)

    conn = init_connection(args.server,args.port)
    
    initMsg = f'init|{clientID}|{args.location}'

    conn.send(encrypt(initMsg,aesKey,aesIV))

    location = args.location.strip('[')
    location = location.strip(']')
    location = location.split(',')
    location = [float(x) for x in location]

    global send_buffer
    send_buffer = queue.Queue()

    global networkStrength
    networkStrength = {}

    environmentBaselineTimer = 0

    channels = args.channels.split(',')
    channelHopInterval = 1 

    print('Waiting for network size')
    size = int(decrypt(conn.recv(1024),aesKey, aesIV))

    print('Waiting for peer list')
    for x in range(0,size):
        data = conn.recv(1024)
        peerInfo = decrypt(data,aesKey,aesIV)
        peerInfo = peerInfo.split('|')
        peerInfo[2] = peerInfo[2].strip('(')
        peerInfo[2] = peerInfo[2].strip(')')
        peerInfo[2] = peerInfo[2].split(',')
        remoteLocation = [float(x) for x in peerInfo[2]]
        print(f'vector for {peerInfo[1]}: {peerInfo[2]}')
        relativeDistance = get_distance_to_client(remoteLocation, location)
        networkStrength[peerInfo[1]] = [relativeDistance, 0]
        acknowledge = encrypt('peer recvd', aesKey,aesIV)
        conn.send(acknowledge)
        
    probeFrame = create_probe_request('WallFly', clientID)

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

    sendp(probeFrame, iface=args.interface, verbose=False)

    loadCount = 0

    print('starting')
    while True:
        try:
            readSockets,_,_ = select.select([conn],[],[],0)
            
            for packet in readSockets:
                data = packet.recv(1024)
                if len(data) == 0:
                      data = None
                
                if not data:
                    print('Server connection closed')
                    conn.close()
                    # print(loadCount)
                    exit()

            while not send_buffer.empty():
                pkt = send_buffer.get()
                data = parse_packet(pkt, args.knownMAC, args.ptValue, args.nValue,location)
                if data:
                    # loadCount+=1
                    conn.sendall(encrypt(data,aesKey,aesIV))

            environmentBaselineTimer += 1
            if environmentBaselineTimer >= 10000000:
                environmentBaselineTimer = 0
                sendp(probeFrame, iface=args.interface, verbose=False)

        except KeyboardInterrupt:
            conn.close()
            exit()
    

if __name__ == '__main__':
    main()