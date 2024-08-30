import sys
import socket
import argparse
import time
import select
import hashlib
from multiprocessing import pool
import pandas as pd
import uuid 

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--address", "-a", default="localhost", help="IP for server")
    parser.add_argument("--port", "-p", default=8505, help="Listening Port")
    parser.add_argument("--databaseAddress", "-da", default=None, help="Database IP")
    parser.add_argument("--databasePort", "-dp", default=None, help="Database port")
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

def read_sockets():
   pass

def privatize(mac):
    hashed = hashlib.sha256(mac.encode(), usedforsecurity=True).hexdigest()
    # print(f'hashed mac:{hashed}')
    return hashed    

def main():

    args = get_args()

    server = init_server(args.address, args.port)    

    db = connect_db(args.databaseAddress, args.databasePort)

    connections = [server]

    serverID = get_mac_address()

    networkPositions, inputSet = init_data_defaults(serverID)

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

            # newLocationData = read_sockets(readSockets)
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
                            connection.send('start'.encode())
                case(3):
                    #send mac list to all connected clients
                    for connection in connections:
                        if connection != server or db:
                            ip,port = connection.getpeername()
                            for key, value in networkPositions.items():
                                # print(f'sending {key}{value} to {ip}:{port}')
                                connection.sendall(f'update|{key}|{value}'.encode())
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
                    exit()
                    
            for connection in readSockets:
                if connection == server:
                    client_connection, address = server.accept()
                    print(f'New connection from {address[0]}')
                    connections.append(client_connection)
                    #client_connection.send(networkPositions.keys.encode())
                else:
                    msg = connection.recv(1024)
                    if not msg:
                        connections.remove(connection)
                    else:
                        msg=msg.decode()
                        data = msg.split('|')
                        if data[0] == 'init':
                            convertedPosition = tuple(float(x) for x in data[2].split(','))
                            networkPositions[data[1]] = convertedPosition
                            continue
                        # data.append(address[0])
                        ip, _ = connection.getpeername()
                        print(f'{ip} sent {data}')
                        hashed_mac = privatize(data[0])
                        rssi = data[1]
                        timestamp = data[2]
                        src = ip
                        row = pd.DataFrame({'mac':[hashed_mac], 'rssi':[rssi], 'time':[timestamp], 'ip':[src]})
                        inputSet = pd.concat([inputSet,row], ignore_index=True)
            pass
            # process_set = getNext(input_set)
            # location = calcPosition(process_set)
            # storeLocation(location)


        except KeyboardInterrupt:
            print(f'Force close detected, shutting down gracefully')
            server.close()
            # print(inputSet.head(10))
            # print(networkPositions.keys)
            exit()


if __name__ == "__main__":
    main()