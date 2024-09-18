import argparse
import select
import sqlite3
import socket
import threading
import json
from datetime import datetime

def get_args():
    parser = argparse.ArgumentParser(description="Simple SQLite Socket Server for Wallfly")
    parser.add_argument("ip", type=str, help="IP of server")
    parser.add_argument("port", type=int, help="Listening Port")
   
    return parser.parse_args()

def init_server(address, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((address, int(port)))
    # server.setblocking(False)
    server.listen()
    return server

# Create SQLite connection and tables
def setup_db():
    db = sqlite3.connect('wallfly.db')
    cursor = db.cursor()

    # Create Table 1
    cursor.execute('''CREATE TABLE IF NOT EXISTS tracking (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        MAC TEXT NOT NULL,
                        Location TEXT,
                        timestamp DATETIME
                      )''')

    # Create Table 2
    cursor.execute('''CREATE TABLE IF NOT EXISTS originaldata (
                        id INTEGER,
                        rssi1 INTEGER, rssi2 INTEGER, rssi3 INTEGER,
                        pt1 REAL, pt2 REAL, pt3 REAL,
                        n1 REAL, n2 REAL, n3 REAL,
                        loc1 TEXT, loc2 TEXT, loc3 TEXT, rssiloc TEXT,
                        FOREIGN KEY(id) REFERENCES table1(id)
                      )''')

    db.commit()
    return db

# Function to insert data into tables
def insert_data(db, data):
    cursor = db.cursor()
    # print(data)
    # Insert into table1
    mac = data['MAC']
    location = str(data['Location'])
    timestamp = data['Timestamp']

    cursor.execute('INSERT INTO tracking (MAC, Location, timestamp) VALUES (?, ?, ?)', 
                   (mac, location, timestamp))
    table1_id = cursor.lastrowid

    # Insert into table2
    # rssi1, rssi2, rssi3 = data['rssi1'], data['rssi2'], data['rssi3']
    # pt1, pt2, pt3 = data['pt1'], data['pt2'], data['pt3']
    # n1, n2, n3 = data['n1'], data['n2'], data['n3']
    # loc1, loc2, loc3 = str(data['loc1']), str(data['loc2']), str(data['loc3'])
    # rssiloc = str(data['rssiloc'])

    # cursor.execute('''INSERT INTO originaldata 
    #                   (id, rssi1, rssi2, rssi3, pt1, pt2, pt3, n1, n2, n3, loc1, loc2, loc3, rssiloc) 
    #                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
    #                (table1_id, rssi1, rssi2, rssi3, pt1, pt2, pt3, n1, n2, n3, loc1, loc2, loc3, rssiloc))
    
    db.commit()

# Function to handle SQL queries
def handle_query(db, query):
    cursor = db.cursor()
    try:
        cursor.execute(query)
        results = cursor.fetchall()
        return json.dumps(results)  # Send results back as JSON
    except sqlite3.Error as e:
        return json.dumps({"error": str(e)})

# Handle each client connection
def handle_client(request, db):
    try:
        # request = client_socket.recv(1024).decode('utf-8')
        data = json.loads(request)

        if data.get("type") == "insert":
            # Handle insert data
            insert_data(db, data)
            # client_socket.send(b"Data received and inserted successfully.")
            response = 'Data received and inserted successfully.'
        elif data.get("type") == "query":
            # Handle SQL query
            query = data.get("query")
            # print(f'QUERY: {query}')
            if query:
                response = handle_query(db, query)
                # client_socket.send(response.encode('utf-8'))
            else:
                # client_socket.send(b"Invalid query format.")
                response = 'invalid query format'
        else:
            pass
            # client_socket.send(b"Unknown request type.")
            response = 'unsupported request type'
    except Exception as e:
        print(f"Error: {e}")
        response = f'Error: {e}'
        # client_socket.send(b"Failed to process request.")
    # finally:
    #     client_socket.close()
    finally:
        return response


# Server function
def main():
    
    args = get_args()
    db = setup_db()
    server = init_server(args.ip, args.port)
    connections = [server]
    print(f"Listening on {args.ip}:{args.port}")

    while True:
        try:
            readSockets,_,_ = select.select(connections,[],[],0)
            # client_socket, addr = server.accept()
            # print(f"Accepted connection from {addr}")
            # client_handler = threading.Thread(target=handle_client, args=(client_socket, conn))
            # client_handler.start()
            for connection in readSockets:
                if connection == server:
                    client_connection, address = server.accept()
                    print(f'New connection from {address[0]}')
                    connections.append(client_connection)
                    #client_connection.send(networkPositions.keys.encode())
                else:
                    msg = connection.recv(2048)
                    msg = msg.decode()
                    if not msg:
                        connections.remove(connection)
                    else:
                        response = handle_client(msg, db)
                        connection.send(response.encode())
        except KeyboardInterrupt:
            print(f'\nForce close detected, shutting down')
            server.close()
            db.close()
            exit()
# Example usage
if __name__ == "__main__":
    main()
