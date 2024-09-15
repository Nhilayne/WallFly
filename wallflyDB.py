import argparse
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

# Create SQLite connection and tables
def setup_db():
    conn = sqlite3.connect('wallfly.db')
    cursor = conn.cursor()

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

    conn.commit()
    return conn

# Function to insert data into tables
def insert_data(conn, data):
    cursor = conn.cursor()
    
    # Insert into table1
    mac = data['MAC']
    location = str(data['Location'])
    timestamp = datetime.utcfromtimestamp(data['timestamp']).strftime('%Y-%m-%d %H:%M:%S')

    cursor.execute('INSERT INTO table1 (MAC, Location, timestamp) VALUES (?, ?, ?)', 
                   (mac, location, timestamp))
    table1_id = cursor.lastrowid

    # Insert into table2
    rssi1, rssi2, rssi3 = data['rssi1'], data['rssi2'], data['rssi3']
    pt1, pt2, pt3 = data['pt1'], data['pt2'], data['pt3']
    n1, n2, n3 = data['n1'], data['n2'], data['n3']
    loc1, loc2, loc3 = str(data['loc1']), str(data['loc2']), str(data['loc3'])
    rssiloc = str(data['rssiloc'])

    cursor.execute('''INSERT INTO table2 
                      (id, rssi1, rssi2, rssi3, pt1, pt2, pt3, n1, n2, n3, loc1, loc2, loc3, rssiloc) 
                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                   (table1_id, rssi1, rssi2, rssi3, pt1, pt2, pt3, n1, n2, n3, loc1, loc2, loc3, rssiloc))
    
    conn.commit()

# Function to handle SQL queries
def handle_query(conn, query):
    cursor = conn.cursor()
    try:
        cursor.execute(query)
        results = cursor.fetchall()
        return json.dumps(results)  # Send results back as JSON
    except sqlite3.Error as e:
        return json.dumps({"error": str(e)})

# Handle each client connection
def handle_client(client_socket, conn):
    try:
        request = client_socket.recv(1024).decode('utf-8')
        data = json.loads(request)

        if data.get("type") == "insert":
            # Handle insert data
            insert_data(conn, data)
            client_socket.send(b"Data received and inserted successfully.")
        elif data.get("type") == "query":
            # Handle SQL query
            query = data.get("query")
            if query:
                response = handle_query(conn, query)
                client_socket.send(response.encode('utf-8'))
            else:
                client_socket.send(b"Invalid query format.")
        else:
            client_socket.send(b"Unknown request type.")
    except Exception as e:
        print(f"Error: {e}")
        client_socket.send(b"Failed to process request.")
    finally:
        client_socket.close()

# Server function
def main():
    args = get_args()
    conn = setup_db()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((args.ip, args.port))
    server.listen(5)
    print(f"Listening on {args.ip}:{args.port}")

    while True:
        client_socket, addr = server.accept()
        print(f"Accepted connection from {addr}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket, conn))
        client_handler.start()

# Example usage
if __name__ == "__main__":
    main()
