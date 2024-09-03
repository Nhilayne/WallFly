import argparse
from scapy.all import *
import pandas as pd



def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", "-i", default="wlan1", help="Network Monitoring Interface")
    parser.add_argument("--channel","-c", default="6", help="Wireless channel to monitor")
    parser.add_argument("--distance", "-d", help="Distance to remote")
    parser.add_argument("--mac", "-m", help="MAC of remote")
    return parser.parse_args()

def channel_set(interface, channel):
    subprocess.call(['iwconfig',interface,'channel',channel])
    print(f'interface {interface} set to channel {channel}')

def packet_handler(pkt):
    if not pkt.haslayer(Dot11):
        return None
    if pkt.type == 0 and pkt.subtype == 4:
        mac_addr = pkt.addr2
        mac_addr = mac_addr.upper()
        rssi = pkt.dBm_AntSignal
        
        # print(f'checking {mac_addr} against listed {key}')
        if mac_addr.upper() == mac.upper():
            data = (f'{mac_addr}|{rssi}|{distance}')
            new_row = pd.DataFrame({'mac': [mac_addr], 'rssi': [rssi], 'distance': [distance]})
            global df
            df = pd.concat([df,new_row], ignore_index=True)
            

def main():

    args = get_args()

    channel_set(args.interface, args.channel)

    global distance
    distance = args.distance
    global mac
    mac = args.mac

    columns = ['mac', 'rssi', 'distance']
    global df
    df = pd.DataFrame(columns=columns)
    # inputSet = pd.concat([inputSet,row], ignore_index=True)

    while True:
        try:
            sniff(iface=args.interface, prn=packet_handler, timeout=0.1)

        except KeyboardInterrupt:
            print('outputting csv')
            df.to_csv('rssi-distance.csv', index=False)
            exit()

if __name__=='__main__':
    main()