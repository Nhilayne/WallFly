import sys
import socket
import argparse
import time
import math
import select
import hashlib
from multiprocessing import pool
import pandas as pd
import uuid 
from collections import defaultdict
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64


##################
# aes 128 key
#f553692b0eeeb0fc14da46a5a26826164511306cebf2b1ef
# iv
#c0dabc32dba054feba4d60c24e7fa50b
##################

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--address", "-a", default="localhost", help="IP for server")
    parser.add_argument("--port", "-p", default=8505, help="Listening Port")
    parser.add_argument("--databaseAddress", "-da", default=None, help="Database IP")
    parser.add_argument("--databasePort", "-dp", default=None, help="Database port")
    parser.add_argument("--knownLocation", "-loc", default=None, help="Static location vector, use with specified mac sniffing on clients")
    #parser.add_argument("--interface", "-i", default="wlan0", help="Network interface")
    return parser.parse_args()

def init_server(address, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((address, int(port)))
    server.setblocking(False)
    server.listen()
    return server

def connect_db(dbAddress, dbPort):
    if dbAddress or dbPort is None:
        print("No database connection, exporting as .csv")
        return None
    else:
        print(f"connecting to database at {dbAddress}:{dbPort} [Currently unimplemented]")
        return None

def get_mac_address():
    id = uuid.getnode()
    id_formatted = ':'.join(('%012x'%id)[i:i+2] for i in range(0,12,2))
    return id_formatted.lower()

def init_data_defaults(serverMac):
    physicalLocations = {serverMac:(0,0,0)}

    # (x,y,z) for an xy floorplan, z as depth
    recvDf = pd.DataFrame(columns=['mac','rssi','time', 'ip'])
    recvDf = recvDf.sort_values(by=['mac', 'time'])

    return physicalLocations, recvDf

def menu(cmd):
    try:
        choice = int(cmd)
    except:
        print('Please enter a number')
        return None
    if choice in range(1,11):
        pass
        # break
    # print('Please enter a valid number')

    return choice

def privatize(mac):
    hashed = hashlib.sha256(mac.encode(), usedforsecurity=True).hexdigest()
    # print(f'hashed mac:{hashed}')
    return hashed    


#Data odering and pass-off
####

def order_data(mac_address, client_id, packet_data, locationKnown=False):
    current_time = time.time()
    
    # Add or update packet data with timestamp for the specific client
    packets[mac_address][client_id] = (packet_data, current_time, locationKnown)

    # Check if we have received packets from 3 unique clients for this MAC address
    if len(packets[mac_address]) == 3:
        process_packets(mac_address, packets.pop(mac_address))

    # After adding the packet, check and clean up old groups
    cleanup_old_groups(current_time)

def process_packets(mac, packet_group):
    # Package the three packets and send them for further processing
    # print(f"Created packet group for {mac}: {packet_group}")
    if locationKnown:
        # format into dataframe, export to csv for external analysis
        print('################__LOC_KNOWN__################')
        print(f"Created packet group for {mac} at {locationKnown}")
        print(packet_group)
        print('#############################################')
    else:
        # actually make prediction or pass to prediction function
        print('#############################################')
        print(f"Created packet group for {mac}")
        print(packet_group)
        print('#############################################')

def cleanup_old_groups(current_time):
    to_remove = []
    for mac_address, client_packets in packets.items():
        # Get the timestamp of the oldest packet in the group
        oldest_timestamp = min(data[1] for data in client_packets.values())
        
        if current_time - oldest_timestamp > 5:
            to_remove.append(mac_address)

    for mac_address in to_remove:
        print(f"Removing stale packets for MAC: {mac_address}")
        del packets[mac_address]

def encrypt(data, key, iv):
    # print(f'encoding {data}')
    data += '&'
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    # data = data.encode()
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(ciphertext)

def decrypt(data, key, iv):
    ciphertext = base64.b64decode(data)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    done = unpadder.update(decrypted) + unpadder.finalize()
    # print(f'decrp: {done}')
    if b'&' in done:
        # print(f'possible oversend found, trimming')
        done = done.split(b'&')[0]
    return done.decode()

def main():

    args = get_args()

    server = init_server(args.address, args.port)    

    db = connect_db(args.databaseAddress, args.databasePort)

    connections = [server]

    serverID = get_mac_address()

    networkPositions, inputSet = init_data_defaults(serverID)

    aesKey = b'f553692b0eeeb0fc14da46a5a2682616'#48
    aesIV = b'c0dabc32dba054fe'#32

    global packets
    packets = defaultdict(dict)  # For storing packets by MAC and client
    global AGE_LIMIT
    AGE_LIMIT = 10  # seconds

    ###############################
    # # calc distance between server and a client node
    # position = tuple(float(x) for x in data[2][1:-1].split(','))
    # print(f'testing::{position[0]}+{position[1]}+{position[2]}')
    # convertedDistance = round(math.sqrt(position[0]**2+position[1]**2+position[2]**2),3)
    # print(f'abs dist: {convertedDistance}')
    # networkBlacklist[data[1]] = convertedDistance
    ###############################

    print(f'\n\nSelect an action:')
    print(f'1: Display Current Connections \t 4: Display Buffer Tail')
    print(f'2: Start Connected Sniffers \t 5: Disconnect Clients')
    print(f'3: Distribute Client List \t 6: Exit')
    while True:
        try:        
            readSockets,_,_ = select.select(connections,[],[],0)
            userInput, _, _ = select.select([sys.stdin], [], [], 0)

            input = None
            if userInput:
                input = menu(sys.stdin.readline().strip())

            match(input):
                case(1):
                    #display all active connections
                    for connection in connections:
                        if connection == server:
                            ip,port = connection.getsockname()
                            print(f'server: {ip}:{port}')
                        elif connection == db:
                            ip,port = connection.getpeername()
                            print(f'database: {ip}:{port}')
                        else:
                            ip,port = connection.getpeername()
                            print(f'client: {ip}:{port}')
                case(2):
                    for connection in connections:
                        if connection != server or db:
                            # connection.send('start'.encode())
                            connection.send(encrypt('start',aesKey,aesIV))
                case(3):
                    #send mac list to all connected clients
                    for connection in connections:
                        if connection != server and connection != db:
                            ip,port = connection.getpeername()
                            for key, value in networkPositions.items():
                                print(f'sending {key}|{value} to {ip}:{port}')
                                # connection.sendall(f'update|{key}|{value}'.encode())
                                connection.sendall(encrypt(f'update|{key}|{value}',aesKey,aesIV))
                case(4):
                    #show recent data
                    print(inputSet.tail(6))
                case(5):
                    #disconnect clients
                    tempConnections = []
                    for connection in connections:
                        if connection != server or db:
                            # print(f'closing {connection}')
                            connection.close()
                        else:
                            tempConnections.append(connection)
                    connections.clear()
                    connections = tempConnections
                case(6):
                    #close out app
                    print('Server stopped')
                    exit()
                    # \r\x95\x0f\x802X\xdc\xb49mX\x93u\x1aOc\xa5vL\x86\xc5\xd0\x18=\r\x9a\xd1\xcc\xe2\xf3\x96h\xb5\xfa\x8e\x12\x06\xf7\xd5\x08
                    # \r\x95\x0f\x802X\xdc\xb55m^\x94uN\x1ac\xf4\x7f|^\x18\xd7+ms\xeb\x1e\xa8\x0b\x11'\xde*\xcc\xdc2\x12\x17\xd1\xea
            for connection in readSockets:
                if connection == server:
                    client_connection, address = server.accept()
                    print(f'New connection from {address[0]}')
                    connections.append(client_connection)
                    #client_connection.send(networkPositions.keys.encode())
                else:
                    msg = connection.recv(2048)
                    msg = decrypt(msg,aesKey,aesIV)
                    if not msg:
                        connections.remove(connection)
                    else:
                        # msg=msg.decode()
                        # print(msg)
                        data = msg.split('|')
                        if data[0] == 'init':
                            data[2] = data[2].strip('[')
                            data[2] = data[2].strip(']')
                            convertedPosition = tuple(float(x) for x in data[2].split(','))
                            networkPositions[data[1]] = convertedPosition
                            # print(f'testing::{convertedPosition[0]}+{convertedPosition[1]}+{convertedPosition[2]}')
                            # convertedDistance = round(math.sqrt(convertedPosition[0]**2+convertedPosition[1]**2+convertedPosition[2]**2),3)
                            # print(f'abs dist: {convertedDistance}')
                            
                            continue
                        # data.append(address[0])

                        ip, _ = connection.getpeername()
                        # print(f'{ip} sent {data}')
                        hashed_mac = privatize(data[0])
                        rssi = data[1]
                        timestamp = data[2]
                        pt = data[3]
                        n = data[4]
                        environment = data[5::]
                        print(f'env: {environment}')
                        # src = ip
                        order_data(hashed_mac, ip, (rssi, timestamp, pt, n, environment), args.knownLocation)
                        # row = pd.DataFrame({'mac':[hashed_mac], 'rssi':[rssi], 'time':[timestamp], 'ip':[src]})
                        # inputSet = pd.concat([inputSet,row], ignore_index=True)
            pass
            # process_set = getNext(input_set)
            # location = calcPosition(process_set)
            # storeLocation(location)


        except KeyboardInterrupt:
            print(f'\nForce close detected, shutting down gracefully')
            server.close()
            # print(inputSet.head(10))
            # print(networkPositions.keys)
            exit()


if __name__ == "__main__":
    main()