import sys
import socket
import argparse
import time
import datetime
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
import joblib
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
    if dbAddress is None or dbPort is None:
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
        return None, None
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

def convert_to_float_list(string):
    try:
        string = string.strip("[]")
        return [float(x) for x in string.split(",")]
    except ValueError:
        return [0.0, 0.0, 0.0]

def apply_binning(df, cols, binList):    
    for col in cols:
        df[col] = pd.cut(df[col], bins=binList, labels=False, include_lowest=True)
        
    return df
    
def get_datetime(epoch):
    dt = datetime.datetime.fromtimestamp(epoch)
    
    # string in 'YYYY-MM-DD HH:MM:SS' format for SQLite.
    return dt.strftime('%Y-%m-%d %H:%M:%S')

def order_data(mac_address, client_id, packet_data, locationKnown=False):
    current_time = time.time()
    processed = None
    # Add or update packet data with timestamp for the specific client
    packets[mac_address][client_id] = (packet_data, locationKnown)

    # Check if we have received packets from 3 unique clients for this MAC address
    if len(packets[mac_address]) == 3:
        processed = process_packets(mac_address, packets.pop(mac_address), locationKnown)

    # After adding the packet, check and clean up old groups
    cleanup_old_groups(current_time)

    return processed

def process_packets(mac, packetGroup, locationKnown):
    # Package the three packets and send them for further processing
    # print(f"Created packet group for {mac}: {packet_group}")
    # print(packetGroup)
    

    keys = list(packetGroup.keys())
    rssi_cols = ['rssi1', 'rssi2', 'rssi3']
    pt_cols = ['pt1', 'pt2', 'pt3']
    n_cols = ['n1', 'n2', 'n3']
    loc_cols = ['loc1', 'loc2', 'loc3']

    firstTimeFound = float(packetGroup[keys[0]][0][1])
    print(f'firstTime: {firstTimeFound}')
    
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
        # building a training set
        global trainSet
        global groupCount
        groupCount += 1
        packetGroupDF['TrueLoc'] = locationKnown
        trainSet = pd.concat([trainSet, packetGroupDF], ignore_index=True)
        print(f'packet groups found: {groupCount}')
        return None
    else:
        # actually make location prediction
        print('#############################################')
        print(f"Created packet group for {mac}")
        global predictionPipeline
        
        predictDF = packetGroupDF

        for col in ['loc1', 'loc2', 'loc3']:
            predictDF[col] = predictDF[col].apply(convert_to_float_list)

        for col in ['loc1', 'loc2', 'loc3']:
            predictDF[col] = predictDF[col].apply(lambda x: x if isinstance(x, list) and len(x) == 3 else [0.0, 0.0, 0.0])

        for col in ['loc1', 'loc2', 'loc3', 'RSSILoc']:
            predictDF[[f'{col}_x', f'{col}_y', f'{col}_z']] = pd.DataFrame(predictDF[col].tolist(), index=predictDF.index)

        #  predictDF.apply(lambda row: rssi_to_dist(row['rssi1'], row['pt1'], row['n1']), axis=1)
        predictDF['distance1'] = d1
        predictDF['distance2'] = d2
        predictDF['distance3'] = d3

        for col in ['rssi1', 'rssi2', 'rssi3']:
            predictDF[col] = predictDF[col].apply(lambda x: int(x) )


        rssiBins = [-100, -70, -65, -60, -55, -50, -45, -40, -35, -30, -25, -20, 0]
        predictDF = apply_binning(predictDF, ['rssi1', 'rssi2', 'rssi3'], rssiBins)

        predictDF = predictDF.drop(columns=['loc1', 'loc2', 'loc3', 'RSSILoc'])
        
        if predictionPipeline:
            # pipeline will handle scaling, polynomial features, PCA, and the model prediction
            predictions = predictionPipeline.predict(predictDF)
            # predictions = np.array_str(predictions[0])
        else:
            # no model found, use base log-distance calc
            predictions = rssiLoc
        
        print(predictions[0])

        timestamp = get_datetime(firstTimeFound)

        data = {'type':'insert','MAC': mac, 'Location': f'[{predictions[0][0]},{predictions[0][1]},{predictions[0][2]}]', 'Timestamp': timestamp}
        print(data)
        print('#############################################')
        #packetGroupDF.to_json(orient='records')[1:-1]
        return json.dumps(data)

def cleanup_old_groups(current_time):
    to_remove = []
    for mac_address, client_packets in packets.items():
        # Get the timestamp of the oldest packet in the group
        oldest_timestamp = min(float(data[0][1]) for data in client_packets.values())
        # print(f'values {client_packets.values()}')
        # print(f'oldest time is {oldest_timestamp}')
        
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

    connections = [server]

    if db:
        connections.append(db)

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

    global predictionPipeline
    try:
        predictionPipeline = joblib.load('wallflyFitModel.pkl')
        print('Prediction model loaded successfully')
    except FileNotFoundError as e:
        print(f'Predictive model file not found: {e}\nLog-Distance estimation will be used')
        predictionPipeline = None
    
    dbBackup = pd.DataFrame()


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
                        if connection != server and connection != db:
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
                        print('No Database connection')
                    else:
                        
                        #convert to db format
                        query = json.dumps({'type': 'query', 'query':query})
                        print(f'query for db: {query}')
                        db.send(query.encode())
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
                    if not msg:
                        connections.remove(connection)
                        print(f'#######\nConnection to Database lost, reverting to csv output\n#######')
                        db = None
                    else:
                        print(msg.decode())
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
                        result = order_data(hashed_mac, ip, (rssi, timestamp, pt, n, loc), args.knownLocation)
                        if result:
                            print(f'Insert to DB:\n{result}')
                            if db:
                                db.send(result.encode())
                            else:
                                result = json.loads(result)
                                resultRow = pd.DataFrame([result])
                                dbBackup = pd.concat([dbBackup, resultRow], ignore_index=True)
                                if dbBackup.shape[0] > 1000:
                                    outputDFCSV(dbBackup, 'wallfly.csv')
                                    dbBackup = pd.DataFrame()
                                

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