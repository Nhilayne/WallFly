            
import argparse
from scapy.all import *
import uuid 
import time

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", "-i", default="wlan1", help="Network Monitoring Interface")
    parser.add_argument("--channel","-c", default="1,6,11", help="Wireless channel to broadcast on")
    return parser.parse_args()

def channel_set(interface, channel):
    subprocess.call(['iwconfig',interface,'channel',channel])
    print(f'interface {interface} set to channel {channel}')

def get_mac_address():
    id = uuid.getnode()
    id_formatted = ':'.join(('%012x'%id)[i:i+2] for i in range(0,12,2))
    return id_formatted.lower()

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

def main():

    args = get_args()

    id = get_mac_address()

    print(f'probe mac: {id}')

    channel_set(args.interface, args.channel)

    while True:
        frame = create_probe_request('WallFly', id)
        sendp(frame, iface=args.interface, verbose=False)
        time.sleep(0.2)
    

if __name__ == '__main__':
    main()