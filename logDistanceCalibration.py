import argparse
from scapy.all import *
import pandas as pd
import math



def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=['pt','n'], help="Distance to remote")
    parser.add_argument("--interface", "-i", default="wlan1", help="Network Monitoring Interface")
    parser.add_argument("--channel","-c", default="6", help="Wireless channel to monitor")
    parser.add_argument("--distance","-d", default="-1", help="Distance to probe emitter in meters")
    parser.add_argument("--ptValue","-pt", default="-30", help="Current PT value for unit")

    
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
            # data = (f'{mac_addr}|{rssi}|{distance}')
            # new_row = {'mac': mac_addr, 'rssi': rssi, 'distance': distance}
            # df = df.append(new_row, ignore_index=True)
            recvList.append(int(rssi))
            

def main():

    args = get_args()

    channel_set(args.interface, args.channel)

    # global distance
    # distance = args.distance
    global mac
    mac = args.mac

    global recvList
    recvList = []

    # columns = ['mac', 'rssi', 'distance']
    # global df
    # df = pd.DataFrame(columns=columns)
    # inputSet = pd.concat([inputSet,row], ignore_index=True)

    while True:
        try:
            sniff(iface=args.interface, prn=packet_handler, timeout=0.5)

        except KeyboardInterrupt:
            # df.to_csv('rssi-distance,csv', index=False)
            if args.mode == 'pt':
                print(f'PT value {sum(recvList)/len(recvList)}, ({sum(recvList)}/{len(recvList)})')
            elif args.mode == 'n':
                currentValue = sum(recvList)/len(recvList)
                currentDistance = float(args.distance)
                distances = []
                values = []
                nValues = []
                with open('calibration.txt','a+') as file:
                    file.seek(0)
                    for line in file:
                        values = line.strip().split(',')
                        distances.append(float(values[0]))
                        values.append(float(values[1]))
                    if currentDistance != -1:
                        distances.append(currentDistance)
                        values.append(currentValue)

                    # for x in range(0,len(distances)):
                    #     nValues = (args.ptValue - values[x]) / (10 * )
                    nValues = [(args.ptValue - rssi) / (10 * math.log10(distance)) for rssi, distance in zip(values, distances)]

                    print(f'Current Calibrated N = {sum(nValues) / len(nValues)}')

                    if currentDistance != -1:
                        file.write(f'{currentDistance}, {currentValue}')
                # print(f'calibration file updated')



            exit()

if __name__=='__main__':
    main()