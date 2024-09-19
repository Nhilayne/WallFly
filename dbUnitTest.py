import unittest
from unittest.mock import patch, MagicMock, mock_open
import sqlite3
import socket
import json
import argparse

# Assuming the functions are imported from your module

from wallflyDB import *

class TestWallflyServer(unittest.TestCase):

    # Test get_args
    @patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(ip='127.0.0.1', port=8080))
    def test_get_args(self, mock_parse_args):
        args = get_args()
        self.assertEqual(args.ip, '127.0.0.1')
        self.assertEqual(args.port, 8080)

    # Test init_server
    @patch('socket.socket')
    def test_init_server(self, mock_socket):
        mock_socket_instance = mock_socket.return_value
        server = init_server('127.0.0.1', 8080)
        mock_socket.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
        mock_socket_instance.bind.assert_called_once_with(('127.0.0.1', 8080))
        mock_socket_instance.listen.assert_called_once()
        self.assertEqual(server, mock_socket_instance)

    # Test setup_db
    @patch('sqlite3.connect')
    def test_setup_db(self, mock_connect):
        mock_connection = mock_connect.return_value
        mock_cursor = mock_connection.cursor.return_value

        db = setup_db()

        # Check if the database connection was made
        mock_connect.assert_called_once_with('wallfly.db')
        # Check if the tables were created
        mock_cursor.execute.assert_any_call('''CREATE TABLE IF NOT EXISTS tracking (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        MAC TEXT NOT NULL,
                        Location TEXT,
                        timestamp DATETIME
                      )''')
        # Check if commit was called
        mock_connection.commit.assert_called_once()

        # Assert the returned db connection is correct
        self.assertEqual(db, mock_connection)

    # Test insert_data
    @patch('sqlite3.connect')
    def test_insert_data(self, mock_connect):
        mock_connection = mock_connect.return_value
        mock_cursor = mock_connection.cursor.return_value

        db = mock_connection
        data = {
            'MAC': 'AA:BB:CC:DD:EE:FF',
            'Location': '10,20,30',
            'Timestamp': '2024-09-17 12:00:00'
        }

        insert_data(db, data)

        # Check if the correct SQL insert was called for the tracking table
        mock_cursor.execute.assert_any_call(
            'INSERT INTO tracking (MAC, Location, timestamp) VALUES (?, ?, ?)',
            ('AA:BB:CC:DD:EE:FF', '10,20,30', '2024-09-17 12:00:00')
        )

        # Check if commit was called after insertion
        mock_connection.commit.assert_called_once()

    # Test handle_query
    @patch('sqlite3.connect')
    def test_handle_query(self, mock_connect):
        mock_connection = mock_connect.return_value
        mock_cursor = mock_connection.cursor.return_value

        db = mock_connection
        query = "SELECT * FROM tracking"
        mock_cursor.fetchall.return_value = [(1, 'AA:BB:CC:DD:EE:FF', '10,20,30', '2024-09-17 12:00:00')]

        response = handle_query(db, query)

        # Check if the query was executed
        mock_cursor.execute.assert_called_once_with(query)

        # Check if the correct results were returned as JSON
        expected_response = json.dumps([(1, 'AA:BB:CC:DD:EE:FF', '10,20,30', '2024-09-17 12:00:00')])
        self.assertEqual(response, expected_response)

    # Test handle_query with error
    @patch('sqlite3.connect')
    def test_handle_query_error(self, mock_connect):
        mock_connection = mock_connect.return_value
        mock_cursor = mock_connection.cursor.return_value
        mock_cursor.execute.side_effect = sqlite3.Error("Some SQL Error")

        db = mock_connection
        query = "SELECT * FROM invalid_table"

        response = handle_query(db, query)

        # Check if the error is handled and returned as JSON
        self.assertEqual(response, json.dumps({"error": "Some SQL Error"}))

    # Test handle_client - Insert request
    @patch('sqlite3.connect')
    def test_handle_client_insert(self, mock_connect):
        mock_connection = mock_connect.return_value
        db = mock_connection

        # Mock a valid insert request
        request = json.dumps({
            'type': 'insert',
            'MAC': 'AA:BB:CC:DD:EE:FF',
            'Location': '10,20,30',
            'Timestamp': '2024-09-17 12:00:00'
        })

        response = handle_client(request, db)

        # Assert that insert_data was called correctly
        self.assertEqual(response, 'Data received and inserted successfully.')

    # Test handle_client - Query request
    @patch('sqlite3.connect')
    def test_handle_client_query(self, mock_connect):
        mock_connection = mock_connect.return_value
        mock_cursor = mock_connection.cursor.return_value
        mock_cursor.fetchall.return_value = [(1, 'AA:BB:CC:DD:EE:FF', '10,20,30', '2024-09-17 12:00:00')]

        db = mock_connection

        # Mock a valid query request
        request = json.dumps({
            'type': 'query',
            'query': 'SELECT * FROM tracking'
        })

        response = handle_client(request, db)

        expected_response = json.dumps([(1, 'AA:BB:CC:DD:EE:FF', '10,20,30', '2024-09-17 12:00:00')])
        self.assertEqual(response, expected_response)

    # Test handle_client - Invalid request type
    @patch('sqlite3.connect')
    def test_handle_client_invalid_type(self, mock_connect):
        mock_connection = mock_connect.return_value
        db = mock_connection

        # Mock an invalid request type
        request = json.dumps({
            'type': 'invalid_type'
        })

        response = handle_client(request, db)

        # Assert the response for unsupported request type
        self.assertEqual(response, 'unsupported request type')

    # Test handle_client - Invalid query
    @patch('sqlite3.connect')
    def test_handle_client_invalid_query(self, mock_connect):
        mock_connection = mock_connect.return_value
        db = mock_connection

        # Mock an invalid query format request
        request = json.dumps({
            'type': 'query',
            'query': ''
        })

        response = handle_client(request, db)

        # Assert the response for invalid query format
        self.assertEqual(response, 'invalid query format')


if __name__ == '__main__':
    unittest.main()
