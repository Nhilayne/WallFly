import unittest
from unittest.mock import patch, MagicMock, call
import socket
import uuid
import hashlib
import pandas as pd
import argparse
import numpy as np
import datetime
import time
import base64
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
from cryptography.hazmat.backends import default_backend
from collections import defaultdict

# Importing the functions from the main module
from server import *

class TestFunctions(unittest.TestCase):

    @patch('argparse.ArgumentParser.parse_args')
    def test_get_args(self, mock_parse_args):
        # Mock the arguments
        mock_parse_args.return_value = argparse.Namespace(
            address="192.168.1.1",
            port=8505,
            databaseAddress="192.168.1.2",
            databasePort=3306,
            knownLocation="1,1,1"
        )
        args = get_args()
        self.assertEqual(args.address, "192.168.1.1")
        self.assertEqual(args.port, 8505)
        self.assertEqual(args.databaseAddress, "192.168.1.2")
        self.assertEqual(args.databasePort, 3306)
        self.assertEqual(args.knownLocation, "1,1,1")

    @patch('socket.socket')
    def test_init_server(self, mock_socket):
        mock_socket_instance = mock_socket.return_value
        server = init_server("localhost", 8505)

        mock_socket.assert_called_with(socket.AF_INET, socket.SOCK_STREAM)
        mock_socket_instance.bind.assert_called_with(("localhost", 8505))
        mock_socket_instance.listen.assert_called()

    @patch('socket.socket')
    def test_connect_db_no_db(self, mock_socket):
        # Test case with no database address or port
        connection = connect_db(None, None)
        self.assertIsNone(connection)

    @patch('socket.socket')
    def test_connect_db_with_db(self, mock_socket):
        # Mock socket connection for the case where db is provided
        mock_socket_instance = mock_socket.return_value
        connection = connect_db("192.168.1.2", 3306)

        mock_socket_instance.connect.assert_called_with(("192.168.1.2", 3306))
        self.assertEqual(connection, mock_socket_instance)

    @patch('uuid.getnode', return_value=0x123456789ABC)
    def test_get_mac_address(self, mock_getnode):
        mac_address = get_mac_address()
        self.assertEqual(mac_address, '12:34:56:78:9a:bc')

    def test_init_data_defaults(self):
        server_mac = "12:34:56:78:9a:bc"
        physical_locations, recv_df = init_data_defaults(server_mac)

        self.assertEqual(physical_locations, {server_mac: (0, 0, 0)})
        self.assertTrue(isinstance(recv_df, pd.DataFrame))
        self.assertListEqual(list(recv_df.columns), ['mac', 'rssi', 'time', 'ip'])
        self.assertEqual(len(recv_df), 0)

    def test_menu_invalid_input(self):
        choice, query = menu("invalid")
        self.assertIsNone(choice)
        self.assertIsNone(query)

    @patch('builtins.input', return_value='query_value')
    def test_menu_valid_input(self, mock_input):
        choice, query = menu("4")
        self.assertEqual(choice, 4)
        self.assertEqual(query, "query_value")

    def test_menu_out_of_range(self):
        choice, query = menu("10")
        self.assertIsNone(choice)
        self.assertIsNone(query)

    def test_privatize(self):
        mac = "12:34:56:78:9a:bc"
        expected_hashed_mac = hashlib.sha256(mac.encode(), usedforsecurity=True).hexdigest()
        result = privatize(mac)
        self.assertEqual(result, expected_hashed_mac)

    def test_rssi_to_dist(self):
        # Simple test case for RSSI to distance conversion
        rssi = -50
        pt = 30
        n = 2
        expected_distance = 10 ** ((pt - rssi) / (10 * n))
        result = rssi_to_dist(rssi, pt, n)
        self.assertEqual(result, expected_distance)

    def test_rssi_loc(self):
        d1, d2, d3 = 10, 15, 20
        locs = ["[0,0,0]", "[10,0,0]", "[0,10,0]"]
        expected_estimate = np.linalg.pinv(np.array([
            [20, 0, 0],
            [0, 20, 0]
        ])).dot(np.array([
            d1**2 - d2**2 + 100,
            d1**2 - d3**2 + 100
        ])).tolist()

        result = rssi_loc(d1, d2, d3, locs)
        self.assertEqual(result, expected_estimate)

    @patch('builtins.print')
    def test_rssi_loc_colinear_locations(self, mock_print):
        # Case where matrix A is singular and an exception is caught
        d1, d2, d3 = 10, 10, 10
        locs = ["[0,0,0]", "[0,0,0]", "[0,0,0]"]
        result = rssi_loc(d1, d2, d3, locs)
        
        mock_print.assert_any_call('Warning: Log-Distance estimate for location will not predict on the X axis')
        mock_print.assert_any_call('Warning: Log-Distance estimate for location will not predict on the Y axis')
        mock_print.assert_any_call('Warning: Log-Distance estimate for location will not predict on the Z axis')

    def test_toa_to_dist(self):
        toa = 2e-6  # seconds
        ref_toa = 1e-6
        c = 3e8
        expected_distance = c * (toa - ref_toa)
        result = toa_to_dist(toa, ref_toa)
        self.assertEqual(result, expected_distance)

    def test_toa_loc(self):
        locs = np.array([[0, 0, 0], [10, 0, 0], [0, 10, 0]])
        distances = [0, 10, 10]
        expected_estimate = np.linalg.pinv(np.array([
            [10, 0, 0],
            [0, 10, 0]
        ])).dot(0.5 * np.array([
            distances[1]**2 - 100,
            distances[2]**2 - 100
        ])).tolist()

        result = toa_loc(locs, distances)
        self.assertEqual(result, expected_estimate)

    def test_convert_to_float_list_valid(self):
        string = "[1.0, 2.0, 3.0]"
        expected_result = [1.0, 2.0, 3.0]
        result = convert_to_float_list(string)
        self.assertEqual(result, expected_result)

    def test_convert_to_float_list_invalid(self):
        string = "invalid"
        expected_result = [0.0, 0.0, 0.0]
        result = convert_to_float_list(string)
        self.assertEqual(result, expected_result)

    def test_apply_binning(self):
        df = pd.DataFrame({'col1': [1, 2, 3, 4, 5]})
        cols = ['col1']
        bin_list = [0, 2, 4, 6]
        expected_result = pd.cut(df['col1'], bins=bin_list, labels=False, include_lowest=True)
        result = apply_binning(df, cols, bin_list)
        pd.testing.assert_series_equal(result['col1'], expected_result)

    def test_get_datetime(self):
        epoch = 1726515000
        expected_datetime = "2024-09-16 12:30:00"
        result = get_datetime(epoch)
        self.assertEqual(result, expected_datetime)

    @patch('time.time', return_value=1694872200)
    @patch('server.cleanup_old_groups')
    @patch('server.process_packets', return_value="processed_data")
    def test_order_data(self, mock_process_packets, mock_cleanup_old_groups, mock_time):
        # Test with 3 unique clients for the same MAC address
        # global packets
        # packets = defaultdict(dict)
        packets['12:34:56:78:9a:bc'] = {
                'client1': ('data1', False),
                'client2': ('data2', False)
            }
        
        mac_address = '12:34:56:78:9a:bc'
        client_id = 'client3'
        packet_data = 'data3'

        processed = order_data(mac_address, client_id, packet_data)

        # Check if the packets were processed when 3 clients' data are present
        self.assertEqual(processed, "processed_data")
        mock_process_packets.assert_called_once_with(mac_address, {
            'client1': ('data1', False),
            'client2': ('data2', False),
            'client3': (packet_data, False)
        }, False)

        # Ensure old groups were cleaned up after processing
        mock_cleanup_old_groups.assert_called_once_with(1694872200)

    @patch('time.time', return_value=1694872200)
    @patch('server.cleanup_old_groups')
    def test_order_data_not_enough_clients(self, mock_cleanup_old_groups, mock_time):
        # global packets
        packets['12:34:56:78:9a:bc'] = {
                'client1': ('data1', False),
                'client2': ('data2', False)
        }
        mac_address = '12:34:56:78:9a:bc'
        client_id = 'client2'
        packet_data = 'data2'

        processed = order_data(mac_address, client_id, packet_data)

        # Since there aren't 3 unique clients yet, no processing should happen
        self.assertIsNone(processed)
        mock_cleanup_old_groups.assert_called_once_with(1694872200)


    @patch('builtins.print')  # Mocking print to suppress output during tests
    @patch('server.apply_binning')  # Replace 'your_module' with the actual module name
    @patch('server.get_datetime')
    @patch('server.rssi_loc')
    @patch('server.rssi_to_dist')
    def test_process_packets_training(self, mock_rssi_to_dist, mock_rssi_loc, mock_get_datetime, mock_apply_binning, mock_print):
        # Setting up mock return values
        mock_rssi_to_dist.side_effect = [10, 15, 20]  # Mock distances
        mock_rssi_loc.return_value = [10.0, 20.0, 30.0]  # Mock RSSI location
        mock_get_datetime.return_value = "2024-09-18 12:00:00"
        
        # Mock input data for training
        mac = "AA:BB:CC:DD:EE:FF"
        packetGroup = {
            1: ([60, 1234567890.0, 30, 2, "[1,1,0]"], True),
            2: ([70, 1234567891.0, 30, 2, "[2,2,0]"], True),
            3: ([80, 1234567892.0, 30, 2, "[3,3,0]"], True)
        }
        locationKnown = '[0,0,0]'
        
        # global trainSet, groupCount
        # trainSet = pd.DataFrame()  # Mock an empty DataFrame
        # groupCount = 0

        result = process_packets(mac, packetGroup, locationKnown)

        self.assertEqual(result[0], 1)
        self.assertEqual(len(result[1]), 1)  # One row should be added to the train set

    @patch('builtins.print')  # Mocking print to suppress output during tests
    @patch('server.get_datetime')
    @patch('server.rssi_loc')
    @patch('server.rssi_to_dist')
    def test_process_packets_no_model(self, mock_rssi_to_dist, mock_rssi_loc, mock_get_datetime, mock_print):
        # Setting up mock return values
        mock_rssi_to_dist.side_effect = [10, 15, 20]  # Mock distances
        mock_rssi_loc.return_value = [10.0, 20.0, 30.0]  # Mock RSSI location
        mock_get_datetime.return_value = "2024-09-18 12:00:00"
        
        # Mock input data for prediction
        mac = "AA:BB:CC:DD:EE:FF"
        packetGroup = {
            1: ([60, 1234567890.0, 30, 2, "[1,1,0]"], False),
            2: ([70, 1234567891.0, 30, 2, "[2,2,0]"], False),
            3: ([80, 1234567892.0, 30, 2, "[3,3,0]"], False)
        }
        locationKnown = False

        global predictionPipeline
        predictionPipeline = None  # No prediction model

        result = process_packets(mac, packetGroup, locationKnown)

        expected_data = {
            'type': 'insert',
            'MAC': mac,
            'Location': '[10.0,20.0,30.0]',
            'Timestamp': '2024-09-18 12:00:00'
        }

        self.assertEqual(result, json.dumps(expected_data))

    @patch('builtins.print')  # Mocking print to suppress output during tests
    @patch('server.apply_binning')
    @patch('server.get_datetime')
    @patch('server.rssi_loc')
    @patch('server.rssi_to_dist')
    @patch('server.predictionPipeline')
    def test_process_packets_prediction(self,mock_predictionPipeline, mock_rssi_to_dist, mock_rssi_loc, mock_get_datetime, mock_apply_binning, mock_print):
        # Setting up mock return values
        mock_rssi_to_dist.side_effect = [10, 15, 20]  # Mock distances
        mock_rssi_loc.return_value = [10.0, 20.0, 30.0]  # Mock RSSI location
        mock_get_datetime.return_value = "2024-09-18 12:00:00"
        
        # Mock input data for prediction
        mac = "AA:BB:CC:DD:EE:FF"
        packetGroup = {
            1: ([60, 1234567890.0, 30, 2, "[1,1,0]"], False),
            2: ([70, 1234567891.0, 30, 2, "[2,2,0]"], False),
            3: ([80, 1234567892.0, 30, 2, "[3,3,0]"], False)
        }
        locationKnown = False

        # global predictionPipeline
        # predictionPipeline = MagicMock()  # Mock the prediction pipeline
        mock_predictionPipeline.predict.return_value = np.array([[10.5, 20.5, 30.5]])  # Mock prediction

        result = process_packets(mac, packetGroup, locationKnown)

        expected_data = {
            "type": "insert",
            "MAC": mac,
            "Location": "[10.5,20.5,30.5]",
            "Timestamp": "2024-09-18 12:00:00"
        }

        self.assertEqual(result, json.dumps(expected_data))



    # Test for cleanup_old_groups
    @patch('builtins.print')  # Mock print to suppress output during tests
    def test_cleanup_old_groups(self, mock_print):
        global packets
        current_time = 1234567895.0  # Simulated current time

        packets['12:34:56:78:9a:bc'] = {
                'client1': (('data1',1234567894.0), False),
                'client2': (('data2',1234567890.0), False),
                'client3': (('data3',1234567880.0), False)
        }
        
        result = cleanup_old_groups(current_time)

        # Check if the old packet is removed and only the recent ones remain
        self.assertNotIn("77:88:99:AA:BB:CC", packets)
        self.assertNotIn("AA:BB:CC:DD:EE:FF", packets)
        self.assertNotIn("11:22:33:44:55:66", packets)

        # Check if the correct print statement is called
        mock_print.assert_called_with("Removing stale packets for MAC: 12:34:56:78:9a:bc")

    # Test for outputDFCSV
    @patch('pandas.DataFrame.to_csv')
    @patch('pandas.io.common.file_exists', return_value=False)
    def test_outputDFCSV(self, mock_file_exists, mock_to_csv):
        df = pd.DataFrame({
            'col1': [1, 2, 3],
            'col2': ['a', 'b', 'c']
        })
        filename = "test_output.csv"
        
        # Call the function
        outputDFCSV(df, filename)
        
        # Assert that to_csv was called with the right parameters
        mock_to_csv.assert_called_once_with(filename, mode='a', header=True, index=False)

    # Test for encrypt
    def test_encrypt(self):
        data = "test_data"
        key = b'f553692b0eeeb0fc14da46a5a2682616'
        iv = b'c0dabc32dba054fe'
        
        # Call the function
        encrypted = encrypt(data, key, iv)
        
        # Decrypt to verify correctness
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(base64.b64decode(encrypted)) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()

        # Assert that the decrypted data matches the original (including the appended '&')
        self.assertEqual(decrypted.decode(), "test_data&")

    # Test for decrypt
    def test_decrypt(self):
        data = "test_data"
        key = b'f553692b0eeeb0fc14da46a5a2682616'
        iv = b'c0dabc32dba054fe'

        # Encrypt the data first (simulating prior encryption)
        encrypted = encrypt(data, key, iv)

        # Call the decrypt function
        decrypted = decrypt(encrypted, key, iv)

        # Assert that the decrypted data matches the original
        self.assertEqual(decrypted, "test_data")

    # Test decrypt with extra padding characters '&'
    def test_decrypt_with_extra_data(self):
        data = "test_data"
        key = b'f553692b0eeeb0fc14da46a5a2682616'
        iv = b'c0dabc32dba054fe'

        # Encrypt the data first
        encrypted = encrypt(data, key, iv)

        # Simulate extra padding by appending & oversend data
        encrypted_extra = encrypted + base64.b64encode(b'&extra')

        # Call the decrypt function
        decrypted = decrypt(encrypted_extra, key, iv)

        # Assert that the decrypted data is trimmed and matches the original
        self.assertEqual(decrypted, "test_data")

if __name__ == "__main__":
    unittest.main()
