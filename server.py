import sys
import socket
import argparse
import time
import datetime
import select
import hashlib
import pandas as pd
import uuid 
from collections import defaultdict
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import numpy as np
import joblib
import json

##################
# globals
packets = defaultdict(dict) 
trainSet = pd.DataFrame()
groupCount = 0
distanceModel = None
predictionPipeline = None
##################

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--address", "-a", default="localhost", help="IP of server")
    parser.add_argument("--port", "-p", default=8505, help="Listening Port")
    parser.add_argument("--databaseAddress", "-da", default=None, help="Database IP")
    parser.add_argument("--databasePort", "-dp", default=None, help="Database port")
    parser.add_argument("--knownLocation", "-loc", default=None, help="Static location vector, use with specified mac sniffing on clients")
    return parser.parse_args()

def init_server(address, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((address, int(port)))
    server.listen()
    return server

def connect_db(dbAddress, dbPort):
    if dbAddress is None or dbPort is None:
        print("No database connection, tracking results will be saved to wallfly.csv")
        return None
    else:
        print(f"Connecting to database at {dbAddress}:{dbPort}...")
        try:
            connection = socket.socket()
            connection.connect((dbAddress, int(dbPort)))
            print('Success')
            return connection
        except ConnectionRefusedError:
            print(f'Connection to database at {dbAddress}:{dbPort} refused, tracking results will be saved to wallfly.csv')
            return None
        
def get_mac_address():
    id = uuid.getnode()
    id_formatted = ':'.join(('%012x'%id)[i:i+2] for i in range(0,12,2))
    return id_formatted.lower()

def init_data_defaults(serverMac):
    # (x,y,z) for an xy floorplan, z as depth
    physicalLocations = {serverMac:(0,0,0)}    
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
    else:
        choice = None

    return choice, query

def privatize(mac):
    hashed = hashlib.sha256(mac.encode(), usedforsecurity=True).hexdigest()
    return hashed    

def rssi_to_dist(rssi, pt, n):
    return 10**((float(pt)-float(rssi)) / (10*float(n)))

def rssi_loc(d1,d2,d3,locs):
    if type(locs[0]) is str:
        loc1 = (float(x) for x in locs[0].strip('[]').split(','))
        loc2 = (float(x) for x in locs[1].strip('[]').split(','))
        loc3 = (float(x) for x in locs[2].strip('[]').split(','))
    else:
        loc1 = locs[0]
        loc2 = locs[1]
        loc3 = locs[2]
    x1,y1,z1 = loc1
    x2,y2,z2 = loc2
    x3,y3,z3 = loc3

    if x1 == x2 == x3:
        print('Warning: Estimate for location will not predict on the X axis')
    if y1 == y2 == y3:
        print('Warning: Estimate for location will not predict on the Y axis')
    if z1 == z2 == z3:
        print('Warning: Estimate for location will not predict on the Z axis')

    A = np.array([
        [2*(x2-x1),2*(y2-y1),2*(z2-z1)],
        [2*(x3-x1),2*(y3-y1),2*(z3-z1)],
    ])
    
    B = np.array([
        d1**2 - d2**2 + x2**2 - x1**2 + y2**2 - y1**2 + z2**2 - z1**2,
        d1**2 - d3**2 + x3**2 - x1**2 + y3**2 - y1**2 + z3**2 - z1**2,
    ])

    
    estimate = np.linalg.pinv(A).dot(B).tolist()
    estimate = np.around(estimate, decimals=2).tolist()
    
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
    global packets
    current_time = time.time()
    processed = None
    # Add or update packet data with timestamp for the specific client
    packets[mac_address][client_id] = (packet_data, locationKnown)

    # Check if we have received packets from 3 unique clients for this MAC address
    if len(packets[mac_address]) == 3:
        processed = process_packets(mac_address, packets.pop(mac_address), locationKnown)

    # After adding the packet, check and clean up old groups
    cleanup_old_groups(current_time)

    if processed is type(tuple):
        return

    return processed

def process_packets(mac, packetGroup, locationKnown):
    predictions = None
    keys = list(packetGroup.keys())
    rssi_cols = ['rssi1', 'rssi2', 'rssi3']
    pt_cols = ['pt1', 'pt2', 'pt3']
    n_cols = ['n1', 'n2', 'n3']
    loc_cols = ['loc1', 'loc2', 'loc3']

    firstTimeFound = float(packetGroup[keys[0]][0][1])
    
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


    d1 = rssi_to_dist(packetGroupDF.at[0,'rssi1'],packetGroupDF.at[0,'pt1'],packetGroupDF.at[0,'n1'])
    d2 = rssi_to_dist(packetGroupDF.at[0,'rssi2'],packetGroupDF.at[0,'pt2'],packetGroupDF.at[0,'n2'])
    d3 = rssi_to_dist(packetGroupDF.at[0,'rssi3'],packetGroupDF.at[0,'pt3'],packetGroupDF.at[0,'n3'])
    rssiLoc = rssi_loc(d1,d2,d3,[packetGroupDF.at[0,'loc1'],packetGroupDF.at[0,'loc2'],packetGroupDF.at[0,'loc3']])
    packetGroupDF['RSSILoc'] = None
    packetGroupDF.at[0,'RSSILoc'] = rssiLoc
    
    if locationKnown:
        # building a training set
        global trainSet
        global groupCount
        groupCount += 1
        packetGroupDF['TrueLoc'] = locationKnown
        trainSet = pd.concat([trainSet, packetGroupDF], ignore_index=True)
        # print(f'packet groups found: {groupCount}')
        return (groupCount, trainSet)
    else:
        # actually make location prediction
        predictDF = packetGroupDF

        for col in ['loc1', 'loc2', 'loc3']:
            predictDF[col] = predictDF[col].apply(convert_to_float_list)

        for col in ['loc1', 'loc2', 'loc3']:
            predictDF[col] = predictDF[col].apply(lambda x: x if isinstance(x, list) and len(x) == 3 else [0.0, 0.0, 0.0])

        for col in ['loc1', 'loc2', 'loc3', 'RSSILoc']:
            predictDF[[f'{col}_x', f'{col}_y', f'{col}_z']] = pd.DataFrame(predictDF[col].tolist(), index=predictDF.index)

        if distanceModel is None:
            predictions = [rssiLoc]
        else:
            predictDF['distance1'] = predictDF.apply(lambda row: distanceModel.predict(pd.DataFrame({
                'rssi': [row['rssi1']],
                'pt': [row['pt1']],
                'n': [row['n1']],
                'rssidist': [d1]
            }))[0], axis=1)
            predictDF['distance2'] = predictDF.apply(lambda row: distanceModel.predict(pd.DataFrame({
                'rssi': [row['rssi2']],
                'pt': [row['pt2']],
                'n': [row['n2']],
                'rssidist': [d2]
            }))[0], axis=1)
            predictDF['distance3'] = predictDF.apply(lambda row: distanceModel.predict(pd.DataFrame({
                'rssi': [row['rssi3']],
                'pt': [row['pt3']],
                'n': [row['n3']],
                'rssidist': [d3]
            }))[0], axis=1)
       
            predictDF['locest'] = predictDF.apply(lambda row: rssi_loc(
                row['distance1'], 
                row['distance2'], 
                row['distance3'], 
                [(row['loc1_x'],row['loc1_y'],row['loc1_z']),
                (row['loc2_x'],row['loc2_y'],row['loc2_z']),
                (row['loc3_x'],row['loc3_y'],row['loc3_z'])
                ]), axis=1)
            
            impLoc = predictDF.at[0,'locest']
            print(f'imploc: {impLoc}')
            
            for col in ['locest']:
                predictDF[col] = predictDF[col].apply(lambda x: x if isinstance(x, list) and len(x) == 3 else [0.0, 0.0, 0.0])

            for col in ['locest']:
                predictDF[[f'{col}_x', f'{col}_y', f'{col}_z']] = pd.DataFrame(predictDF[col].tolist(), index=predictDF.index)
                
        if predictionPipeline and distanceModel:
            X = predictDF.drop(columns=['loc1','loc2','loc3','RSSILoc','locest'])
            try:
                predictions = predictionPipeline.predict(X)
            except:
                print('predict failed')
                print(X.tail(1))
                predictions = [impLoc]
        elif distanceModel:
            # no model found, use base log-distance calc
            predictions = [impLoc]
        
        # print(f'final pred: {predictions}')

        timestamp = get_datetime(firstTimeFound)

        data = {'type':'insert','MAC': mac, 'Location': f'[{predictions[0][0]},{predictions[0][1]},{predictions[0][2]}]', 'Timestamp': timestamp}

        return json.dumps(data)

def cleanup_old_groups(current_time):
    to_remove = []
    for mac_address, client_packets in packets.items():
        # Get the timestamp of the oldest packet in the group
        oldest_timestamp = min(float(data[0][1]) for data in client_packets.values())
        
        if current_time - oldest_timestamp > 10:
            to_remove.append(mac_address)
    for mac_address in to_remove:
        # print(f"Removing stale packets for MAC: {mac_address}")
        del packets[mac_address]

def outputDFCSV(outputDF, filename):
    outputDF.to_csv(filename, mode='a', header=not pd.io.common.file_exists(filename),index=False)

def encrypt(data, key, iv):
    # print(f'encoding {data}')
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
    try:
        decrypted = decrypted.decode()
    except UnicodeDecodeError:
        return None
    return decrypted


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

    aesKey = b'f553692b0eeeb0fc14da46a5a2682616'#32
    aesIV = b'c0dabc32dba054fe'#16

    global distanceModel
    try:
        distanceModel = joblib.load('distanceModel.pkl')
        print('Distance model loaded successfully')
    except FileNotFoundError as e:
        print(f'Distance model not found: {e}\nPath-loss distance estimation will be used')
    
    global predictionPipeline
    try:
        predictionPipeline = joblib.load('wallflyFitModel3.pkl')
        
        if distanceModel:
            print('Location model loaded successfully')
        else:
            print('Missing Distance model, cannot align Location model:\n Matrix location estimation will be used')
    except FileNotFoundError as e:
        print(f'Location model not found: {e}\nMatrix location estimation will be used')
        # predictionPipeline = None
    
    dbBackup = pd.DataFrame()

    loadCount = 0
    outputString = ''

    print(f'\n\nSelect an action:')
    print(f'1: Display Current Connections \t 4: Output DB Query')
    print(f'2: Distribute Netwok Size \t 5: Disconnect Clients')
    print(f'3: Distribute Peers and Start \t 6: Exit')
    while True:
        try:        
            readSockets,_,_ = select.select(connections,[],[],0)
            userInput, _, _ = select.select([sys.stdin], [], [], 0)

            input = None
            if userInput:
                input, query = menu(sys.stdin.readline().strip())

            match(input):
                case(1):
                    peerNum = 0
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
                            connection.send(encrypt(f'{peerNum}',aesKey,aesIV))
                    print('Done')
                case(3):
                    print('Distributing Peer List...')
                    for connection in connections:
                        if connection != server and connection != db:
                            ip,port = connection.getpeername()
                            for key, value in networkPositions.items():
                                data = encrypt(f'|{key}|{value}',aesKey,aesIV)
                                connection.sendall(data)
                                resp = connection.recv(1024)
                    print('Done')
                case(4):
                    if db is None:
                        print('No Database connection')
                    else:
                        query = json.dumps({'type': 'query', 'query':query})
                        print(f'query for db: {query}')
                        query += '&'
                        db.send(query.encode())
                case(5):
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
                    print('Server stopped')
                    # print(f'total recv {loadCount}')
                    for connection in connections:
                        connection.close()
                    outputDFCSV(dbBackup, 'wallfly.csv')
                    outputDFCSV(trainSet, 'trainSet.csv')
                    exit()
            
            for connection in readSockets:
                if connection == server:
                    client_connection, address = server.accept()
                    print(f'New connection from {address[0]}')
                    connections.append(client_connection)
                elif connection == db:
                    msg = connection.recv(2048)
                    if not msg:
                        connections.remove(connection)
                        print(f'#######\nConnection to Database lost, reverting to csv output\n#######')
                        db = None
                    else:
                        msg = msg.decode()
                        if msg[0] == '&':
                            print(msg[1:])
                            continue
                        outputString += msg
                        if outputString[-1] == '&':
                            entryList = json.loads(outputString[0:-1])
                            for x in entryList:
                                print(x)
                            outputString = ''
                else:
                    msg = connection.recv(1024)
                    
                    if not msg:
                        print(f'Lost Connection with {connection}, resetting...')
                        for connection in connections:
                            if connection != server and connection != db:
                                print(f'closing {connection}')
                                connection.close()
                            else:
                                tempConnections.append(connection)
                        connections.clear()
                        connections = tempConnections
                        peerNum = 0
                    else:
                        msg = decrypt(msg,aesKey,aesIV)
                        if msg is None:
                            continue
                        data = msg.split('|')
                        if data[0] == 'init':
                            data[2] = data[2].strip('[')
                            data[2] = data[2].strip(']')
                            convertedPosition = tuple(float(x) for x in data[2].split(','))
                            networkPositions[data[1]] = convertedPosition                            
                            continue

                        ip, _ = connection.getpeername()
                        try:
                            hashed_mac = privatize(data[0])
                            rssi = data[1]
                            timestamp = data[2]
                            pt = data[3]
                            n = data[4]
                            loc = data[5]
                        except IndexError:
                            continue
                        if rssi == 'None':
                            rssi = 0
                        result = order_data(hashed_mac, ip, (rssi, timestamp, pt, n, loc), args.knownLocation)
                        if result:
                            if db:
                                result += '&'
                                db.sendall(result.encode())
                            else:
                                result = json.loads(result)
                                resultRow = pd.DataFrame([result])
                                resultRow = resultRow.drop(columns=['type'])
                                dbBackup = pd.concat([dbBackup, resultRow], ignore_index=True)
                                if dbBackup.shape[0] > 1000:
                                    outputDFCSV(dbBackup, 'wallfly.csv')
                                    dbBackup = pd.DataFrame()
                                
                        # loadCount+=1


        except KeyboardInterrupt:
            print(f'\nForce close detected, shutting down gracefully')
            for connection in connections:
                connection.close()
            outputDFCSV(dbBackup, 'wallfly.csv')
            outputDFCSV(trainSet, 'trainSet.csv')
            exit()


if __name__ == "__main__":
    main()