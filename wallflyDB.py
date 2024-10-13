import argparse
import select
import sqlite3
import socket
import json

def get_args():
    parser = argparse.ArgumentParser(description="Simple SQLite Socket Server for Wallfly")
    parser.add_argument("ip", type=str, help="IP of server")
    parser.add_argument("port", type=int, help="Listening Port")
   
    return parser.parse_args()

def init_server(address, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((address, int(port)))
    server.listen()
    return server

def setup_db():
    db = sqlite3.connect('wallfly.db')
    cursor = db.cursor()

    cursor.execute('''CREATE TABLE IF NOT EXISTS tracking (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        MAC TEXT NOT NULL,
                        Location TEXT,
                        timestamp DATETIME
                      )''')

    db.commit()
    return db

def insert_data(db, data):
    cursor = db.cursor()
    mac = data['MAC']
    location = str(data['Location'])
    timestamp = data['Timestamp']

    cursor.execute('INSERT INTO tracking (MAC, Location, timestamp) VALUES (?, ?, ?)', 
                   (mac, location, timestamp))
    db.commit()

def handle_query(db, query):
    cursor = db.cursor()
    try:
        cursor.execute(query)
        results = cursor.fetchall()
        return json.dumps(results) +'&'
    except sqlite3.Error as e:
        print('sqlite error in query')
        return '&'+json.dumps({"error": str(e)})

def handle_client(request, db):
    try:
        data = json.loads(request)

        if data.get("type") == "insert":
            insert_data(db, data)
            response = '&Data received and inserted successfully.'
        elif data.get("type") == "query":
            query = data.get("query")
            if query:
                response = handle_query(db, query)
            else:
                response = '&Invalid query format'
        else:
            response = '&Unsupported request type'
    except Exception as e:
        print(f"Error: {e}")
        response = f'&Error: {e}'
    finally:
        return response

def main():
    
    args = get_args()
    db = setup_db()
    server = init_server(args.ip, args.port)
    connections = [server]
    print(f"Listening on {args.ip}:{args.port}")

    while True:
        try:
            readSockets,_,_ = select.select(connections,[],[],0)
            for connection in readSockets:
                if connection == server:
                    client_connection, address = server.accept()
                    print(f'New connection from {address[0]}')
                    connections.append(client_connection)
                else:
                    msg = connection.recv(2048)
                    msg = msg.decode()
                    if not msg:
                        connections.remove(connection)
                    else:
                        batch = msg.split('&')
                        for x in batch:
                            if not x:
                                continue
                            response = handle_client(x, db)
                            connection.send(response.encode())
        except KeyboardInterrupt:
            print(f'\nForce close detected, shutting down')
            server.close()
            db.close()
            exit()

if __name__ == "__main__":
    main()
