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
import numpy as np
import sqlite3
import json


##################
# aes 128 key
#f553692b0eeeb0fc14da46a5a26826164511306cebf2b1ef
# iv
#c0dabc32dba054feba4d60c24e7fa50b
##################

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--address", "-a", default="localhost", help="IP of server")
    parser.add_argument("--port", "-p", default=8505, help="Listening Port")
    parser.add_argument("--databaseAddress", "-da", default=None, help="Database IP")
    parser.add_argument("--databasePort", "-dp", default=None, help="Database port")
    parser.add_argument("--knownLocation", "-loc", default=None, help="Static location vector, use with specified mac sniffing on clients")
    #parser.add_argument("--interface", "-i", default="wlan0", help="Network interface")
    return parser.parse_args()

def init_server(address, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((address, int(port)))
    # server.setblocking(False)
    server.listen()
    return server

def connect_db(dbAddress, dbPort):
    if dbAddress or dbPort is None:
        print("No database connection, only tracking results will be saved to wallfly.csv")
        return None
    else:
        print(f"connecting to database at {dbAddress}:{dbPort}")
        connection = socket.socket()
        connection.connect((dbAddress, int(dbPort)))
        return connection

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
        query = None
        choice = int(cmd)
    except:
        print('Please enter a number')
        return None
    if choice in range(1,7):
        if choice == 4:
            query = input()
        # break
    # print('Please enter a valid number')

    return choice, query

def privatize(mac):
    hashed = hashlib.sha256(mac.encode(), usedforsecurity=True).hexdigest()
    # print(f'hashed mac:{hashed}')
    return hashed    

def rssi_to_dist(rssi, pt, n):
    return 10**((float(pt)-float(rssi)) / (10*float(n)))

def rssi_loc(d1,d2,d3,locs):

    loc1 = (float(x) for x in locs[0].strip('[]').split(','))
    loc2 = (float(x) for x in locs[1].strip('[]').split(','))
    loc3 = (float(x) for x in locs[2].strip('[]').split(','))
    x1,y1,z1 = loc1
    x2,y2,z2 = loc2
    x3,y3,z3 = loc3

    A = np.array([
        [2*(x2-x1),2*(y2-y1),2*(z2-z1)],
        [2*(x3-x1),2*(y3-y1),2*(z3-z1)],
    ])
    
    B = np.array([
        d1**2 - d2**2 + x2**2 - x1**2 + y2**2 - y1**2 + z2**2 - z1**2,
        d1**2 - d3**2 + x3**2 - x1**2 + y3**2 - y1**2 + z3**2 - z1**2,
    ])

    try:
        estimate = np.linalg.pinv(A).dot(B).tolist()
    except np.linalg.LinAlgError:
        print('Singular matrix no solution found')
    
    return estimate

def toa_to_dist(toa, ref_toa):
    c = 3e8
    return c * (toa - ref_toa)

def toa_loc(locs, distances):
    A = np.array([
        [locs[1][0] - locs[0][0],
         locs[1][1] - locs[0][1],
         locs[1][2] - locs[0][2]],
        [locs[2][0] - locs[0][0],
         locs[2][1] - locs[0][1],
         locs[2][2] - locs[0][2]],
    ])
    B = 0.5 * np.array([
        distances[1]**2 - np.sum(locs[1]**2) + np.sum(locs[0]**2),
        distances[2]**2 - np.sum(locs[2]**2) + np.sum(locs[0]**2),
    ])

    estimate = np.linalg.pinv(A).dot(B).tolist()

    return estimate

def order_data(mac_address, client_id, packet_data, locationKnown=False):
    current_time = time.time()
    
    # Add or update packet data with timestamp for the specific client
    packets[mac_address][client_id] = (packet_data, current_time, locationKnown)

    # Check if we have received packets from 3 unique clients for this MAC address
    if len(packets[mac_address]) == 3:
        process_packets(mac_address, packets.pop(mac_address), locationKnown)

    # After adding the packet, check and clean up old groups
    cleanup_old_groups(current_time)

def process_packets(mac, packetGroup, locationKnown):
    # Package the three packets and send them for further processing
    # print(f"Created packet group for {mac}: {packet_group}")
    # print(packetGroup)
    

    keys = list(packetGroup.keys())
    rssi_cols = ['rssi1', 'rssi2', 'rssi3']
    pt_cols = ['pt1', 'pt2', 'pt3']
    n_cols = ['n1', 'n2', 'n3']
    loc_cols = ['loc1', 'loc2', 'loc3']

    
    # for i in range(len(keys)):
    #     print(i)
    #     print(packetGroup[keys[i]][0]) 
    # print('####')
    
    # Create DataFrame
    packetGroupDF = pd.DataFrame({
        rssi_cols[i]: [packetGroup[keys[i]][0][0]] for i in range(len(keys))
    },index=[0]).assign(**{
        pt_cols[i]: [packetGroup[keys[i]][0][2]] for i in range(len(keys))
    }).assign(**{
        n_cols[i]: [packetGroup[keys[i]][0][3]] for i in range(len(keys))
    }).assign(**{
        loc_cols[i]: [packetGroup[keys[i]][0][4]] for i in range(len(keys))
    })

    # print(packetGroupDF.head())

    d1 = rssi_to_dist(packetGroupDF.at[0,'rssi1'],packetGroupDF.at[0,'pt1'],packetGroupDF.at[0,'n1'])
    d2 = rssi_to_dist(packetGroupDF.at[0,'rssi2'],packetGroupDF.at[0,'pt2'],packetGroupDF.at[0,'n2'])
    d3 = rssi_to_dist(packetGroupDF.at[0,'rssi3'],packetGroupDF.at[0,'pt3'],packetGroupDF.at[0,'n3'])
    rssiLoc = rssi_loc(d1,d2,d3,[packetGroupDF.at[0,'loc1'],packetGroupDF.at[0,'loc2'],packetGroupDF.at[0,'loc3']])
    # print(rssiLoc)
    packetGroupDF['RSSILoc'] = None
    packetGroupDF.at[0,'RSSILoc'] = rssiLoc

    # # packetGroupDF['ToALoc'] = toa_loc()
    # packetGroupDF['TrueLoc'] = locationKnown

    if locationKnown:
        global trainSet
        global groupCount

        groupCount += 1
        packetGroupDF['TrueLoc'] = locationKnown
        # print(packetGroupDF.head())
        trainSet = pd.concat([trainSet, packetGroupDF], ignore_index=True)

        print(f'packet groups found: {groupCount}')
        # format into dataframe, export to csv for external analysis
        # print('################__LOC_KNOWN__################')
        # print(f"Created packet group for {mac} at {locationKnown}")
        # print(packet_group)
        # print('#############################################')
    else:
        # actually make prediction or pass to prediction function
        print('#############################################')
        print(f"Created packet group for {mac}")
        # print(packetGroup)

        # MAC is string, Location is 3d vector, TimeStamp is datetime from unix epoch
        data = {'MAC': [10], 'Location': [20], 'TimeStamp': [30]}
        
        newRow = pd.DataFrame(data)
        try:
            newRow.to_csv('wallfly.csv', mode='a', header=False, index=False)
        except PermissionError:
            print("The file is open in another program and cannot be written to.")

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

def outputDFCSV(outputDF, filename):
    outputDF.to_csv(filename, mode='a', header=not pd.io.common.file_exists(filename),index=False)

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

    connections = [server, db]

    serverID = get_mac_address()

    networkPositions, inputSet = init_data_defaults(serverID)

    peerNum = 0

    aesKey = b'f553692b0eeeb0fc14da46a5a2682616'#48
    aesIV = b'c0dabc32dba054fe'#32

    global packets
    packets = defaultdict(dict)  # For storing packets by MAC and client
    global AGE_LIMIT
    AGE_LIMIT = 10  # seconds

    global trainSet
    trainSet = pd.DataFrame()
    global groupCount
    groupCount = 0

    ###############################
    # # calc distance between server and a client node
    # position = tuple(float(x) for x in data[2][1:-1].split(','))
    # print(f'testing::{position[0]}+{position[1]}+{position[2]}')
    # convertedDistance = round(math.sqrt(position[0]**2+position[1]**2+position[2]**2),3)
    # print(f'abs dist: {convertedDistance}')
    # networkBlacklist[data[1]] = convertedDistance
    ###############################

    print(f'\n\nSelect an action:')
    print(f'1: Display Current Connections \t 4: Output DB Query')
    print(f'2: Distribute Netwok Size \t 5: Disconnect Clients')
    print(f'3: Distribute Peers and Start \t 6: Exit')
    while True:
        try:        
            readSockets,_,_ = select.select(connections,[],[],0)
            userInput, _, _ = select.select([sys.stdin], [], [], 0)
            # dbOutput,_,_ = select.select(db,[],[],0)

            input = None
            if userInput:
                input, query = menu(sys.stdin.readline().strip())

            match(input):
                case(1):
                    peerNum = 0
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
                            peerNum += 1
                            print(f'client: {ip}:{port}')
                    print(f'{peerNum} peers')
                case(2):
                    print(f'Distributing network size [{peerNum}]...')
                    for connection in connections:
                        if connection != server or db:
                            # connection.send('start'.encode())
                            connection.send(encrypt(f'{peerNum}',aesKey,aesIV))
                    print('Done')
                case(3):
                    #send mac list to all connected clients
                    print('Distributing Peer List...')
                    for connection in connections:
                        if connection != server and connection != db:
                            ip,port = connection.getpeername()
                            for key, value in networkPositions.items():
                                # print(f'sending {key}|{value} to {ip}:{port}')
                                # connection.sendall(f'update|{key}|{value}'.encode())
                                data = encrypt(f'|{key}|{value}',aesKey,aesIV)
                                connection.sendall(data)
                                resp = connection.recv(1024)
                                # print('send loop: '+decrypt(resp,aesKey,aesIV))
                    print('Done')
                case(4):
                    #query DB
                    if db is None:
                        continue
                    print(f'query for db: {query}')
                case(5):
                    #disconnect clients
                    tempConnections = []
                    for connection in connections:
                        if connection != server and connection != db:
                            print(f'closing {connection}')
                            connection.close()
                        else:
                            tempConnections.append(connection)
                    connections.clear()
                    connections = tempConnections
                    peerNum = 0
                case(6):
                    #close out app
                    print('Server stopped')
                    for connection in connections:
                        connection.close()
                    outputDFCSV(trainSet, 'trainSet.csv')
                    exit()
            
            for connection in readSockets:
                if connection == server:
                    client_connection, address = server.accept()
                    print(f'New connection from {address[0]}')
                    connections.append(client_connection)
                    #client_connection.send(networkPositions.keys.encode())
                elif connection == db:
                    msg = connection.recv(2048)
                    print(f'db sent:\n{msg}')
                    #parse more of db output
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
                        loc = data[5]
                        # environment = data[5::]
                        # src = ip
                        order_data(hashed_mac, ip, (rssi, timestamp, pt, n, loc), args.knownLocation)
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