import unittest
from unittest.mock import patch, Mock, MagicMock, ANY
import socket
import uuid
import math
import sys
from scapy.all import *
import datetime
import time
import subprocess
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

from client import *

class TestNetworkModule(unittest.TestCase):

    @patch('sys.argv', ['test_script', '1', '2', '-i', 'eth0'])
    def test_get_args(self):
        args = get_args()
        self.assertEqual(args.ptValue, '1')
        self.assertEqual(args.nValue, '2')
        self.assertEqual(args.interface, 'eth0')

    @patch('socket.socket.connect')
    def test_init_connection(self, mock_connect):
        server = '192.168.4.1'
        port = 8505
        conn = init_connection(server, port)
        mock_connect.assert_called_with((server, port))
        self.assertIsInstance(conn, socket.socket)

    @patch('uuid.getnode', return_value=0x123456789ABC)
    def test_get_mac_address(self, mock_getnode):
        mac_address = get_mac_address()
        self.assertEqual(mac_address, '12:34:56:78:9a:bc')
        # a0:51:0b:d1:cf:18

    def test_get_distance_to_client(self):
        remote_position = [10, 10, 10]
        local_position = [0, 0, 0]
        distance = get_distance_to_client(remote_position, local_position)
        self.assertEqual(distance, round(math.sqrt(10**2 + 10**2 + 10**2), 3))
    
    @patch('client.Dot11')
    def test_parse_packet(self, MockDot11):
        # Create a mock packet
        mock_packet = Mock()
        mock_packet.haslayer.return_value = True
        mock_packet.type = 0
        mock_packet.subtype = 4
        mock_packet.addr2 = "00:11:22:33:44:55"
        mock_packet.dBm_AntSignal = -42
        mock_packet.time = 1234567890

        filter_mac = "00:11:22:33:44:55"
        pt = "100"
        n = "2"
        location = "0,0,0"
        
        result = parse_packet(mock_packet, filter_mac, pt, n, location)
        self.assertEqual(result, "00:11:22:33:44:55|-42|1234567890|100|2|0,0,0")

    def test_create_probe_request(self):
        ssid = "TestSSID"
        id = "00:11:22:33:44:55"
        probe_request = create_probe_request(ssid, id)
        
        # Assert probe request structure
        self.assertEqual(probe_request.addr2, id)
        self.assertEqual(probe_request[Dot11Elt].info, ssid.encode())
    
    @patch('time.sleep', return_value=None)  # Mock sleep to avoid waiting
    @patch('datetime.datetime')
    def test_synchronized_start(self, mock_datetime, mock_sleep):
        
        fixed_time = datetime.datetime(2024,9,16,12,30,45,500000)
        mock_datetime.now.return_value = fixed_time
        
        synchronized_start()

        # Check if sleep was called with the correct calculated time
        current_time = fixed_time
        time_to_wait = 10.-(current_time.microsecond / 1000000.0)
        mock_sleep.assert_called_with(time_to_wait)

    @patch('subprocess.call')
    @patch('time.sleep', return_value=None)  # Mock sleep to avoid waiting
    def test_channel_hopper(self, mock_sleep, mock_subprocess):
        interface = 'wlan1'
        channels = [1, 6, 11]
        interval = 1
        with patch('builtins.print') as mock_print:  # Mock print to avoid printing during the test
            channel_hopper(interface, channels, interval, 1)

        mock_subprocess.assert_any_call(['iwconfig', interface, 'channel', 1])
        mock_subprocess.assert_any_call(['iwconfig', interface, 'channel', 6])
        mock_subprocess.assert_any_call(['iwconfig', interface, 'channel', 11])

    @patch('subprocess.call')
    def test_channel_set(self, mock_subprocess):
        interface = 'wlan0'
        channel = 6
        with patch('builtins.print') as mock_print:  # Mock print to avoid printing during the test
            channel_set(interface, channel)

        mock_subprocess.assert_called_with(['iwconfig', interface, 'channel', channel])
        mock_print.assert_called_with(f'interface {interface} set to channel {channel}')

    @patch('ntplib.NTPClient.request', return_value=MagicMock(tx_time=1694872200))
    @patch('os.system')
    @patch('time.ctime', return_value='Mon Sep 16 12:30:00 2024')
    def test_sync_ntp_time(self, mock_ctime, mock_system, mock_ntp_request):
        with patch('builtins.print') as mock_print:
            sync_ntp_time()
            mock_ntp_request.assert_called_with('192.168.4.1', version=3)
            mock_system.assert_called_with('sudo chronyc makestep')

    @patch('client.sniff')
    def test_capture_packets(self, mock_sniff):
        interface = 'wlan1'
        queue = MagicMock()
        # mock_sniff.side_effect = lambda *args, **kwargs:None
        capture_packets(interface, queue, 1)
        mock_sniff.assert_called_with(iface=interface, prn=ANY, timeout=1, store=0)

    def test_encrypt(self):
        data = "test_data"
        key = b'f553692b0eeeb0fc14da46a5a2682616'  # 16 bytes AES key
        iv = b'c0dabc32dba054fe'  # 16 bytes IV
        encrypted_data = encrypt(data, key, iv)

        # Decode base64 to ensure it's valid
        self.assertIsInstance(encrypted_data, bytes)

    def test_decrypt(self):
        data = "test_data"
        key = b'f553692b0eeeb0fc14da46a5a2682616'
        iv = b'c0dabc32dba054fe'

        # Encrypt the data first
        encrypted_data = encrypt(data, key, iv)
        decrypted_data = decrypt(encrypted_data, key, iv)

        self.assertEqual(decrypted_data, data)

if __name__ == '__main__':
    unittest.main()
