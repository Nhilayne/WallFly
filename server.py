import socket
import argparse
import time
import select
import hashlib
from multiprocessing import pool
import pandas as pd
import uuid 

def get_mac_address():
    id = uuid.getnode()
    id_formatted = ':'.join(('%012x'%id)[i:i+2] for i in range(1,12,2))
    return id_formatted.lower()

def privatize(mac):
    hashed = hashlib.sha256(mac.encode(), usedforsecurity=True).hexdigest()
    print(f'hashed mac:{hashed}')
    return hashed
    
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--address", "-a", default="localhost", help="IP for server")
    parser.add_argument("--port", "-p", default=8505, help="Listening Port")
    parser.add_argument("--database", "-d", help="Database source")
    #parser.add_argument("--interface", "-i", default="wlan0", help="Network interface")
    args = parser.parse_args()
    
    

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((args.address, int(args.port)))
    server.setblocking(False)
    server.listen()

    connections = [server]

    serverID = get_mac_address()

    # (x,y,z) for an xy floorplan, z as depth
    networkPositions = {
        serverID:(0,0,0)
    }


    input_set = pd.DataFrame(columns=['mac','rssi','time', 'ip'])
    input_set = input_set.sort_values(by=['mac', 'time'])

    while True:
        try:        
            read_sockets,_,_ = select.select(connections,[],[],0)
            for connection in read_sockets:
                if connection == server:
                    client_connection, address = server.accept()
                    print(f'New connection from {address[0]}')
                    connections.append(client_connection)
                    client_connection.send(networkPositions.keys.encode())
                else:
                    msg = connection.recv(1024)
                    if not msg:
                        connections.remove(connection)
                    else:
                        msg=msg.decode()
                        data = msg.split('|')
                        # data.append(address[0])
                        # print(data)
                        hashed_mac = privatize(data[0])
                        rssi = data[1]
                        timestamp =data[2]
                        src = address[0]
                        row =pd.DataFrame({'mac':[hashed_mac], 'rssi':[rssi], 'time':[timestamp], 'ip':[src]})
                        input_set = pd.concat([input_set,row], ignore_index=True)
            pass
            # process_set = getNext(input_set)
            # location = calcPosition(process_set)
            # storeLocation(location)


        except KeyboardInterrupt:
            server.close()
            print(input_set.head(10))
            print(networkPositions.keys)
            exit()


if __name__ == "__main__":
    main()