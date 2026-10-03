# test_tcp_server.py
# Asama 9: TCP Server ve Coklu Istemci Otomatik Testleri

import sys
import os
import time
import socket
import threading
import unittest
from pymavlink import mavutil

# Kok dizini python path'ine ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tcp_server import run_tcp_server
from event_logger import _read_events
from behavior_analyzer import clear_history

TEST_TCP_PORT = 14552  # Testler icin cakismayacak ozel port


class TestTCPServer(unittest.TestCase):
    """
    TCP Server ve MAVLink TCP mesajlasma testleri
    """

    @classmethod
    def setUpClass(cls):
        clear_history()
        # Arka planda test TCP server baslat
        cls.stop_event = threading.Event()
        cls.server_thread = threading.Thread(
            target=run_tcp_server,
            kwargs={"host": "127.0.0.1", "port": TEST_TCP_PORT, "stop_event": cls.stop_event},
            daemon=True
        )
        cls.server_thread.start()
        time.sleep(0.3)  # Sunucunun dinlemeye gecmesini bekle

    def setUp(self):
        clear_history()

    @classmethod
    def tearDownClass(cls):
        # Server'i durdur
        cls.stop_event.set()
        cls.server_thread.join(timeout=1.5)

    def _create_mav(self):
        return mavutil.mavlink.MAVLink(None, srcSystem=1, srcComponent=1)

    def test_tcp_heartbeat_normal_with_response(self):
        """TCP uzerinden HEARTBEAT gonderilmeli, NORMAL olmali ve fake HEARTBEAT cevabi donmeli"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", TEST_TCP_PORT))
        client_port = sock.getsockname()[1]

        mav = self._create_mav()
        hb = mav.heartbeat_encode(
            type=mavutil.mavlink.MAV_TYPE_QUADROTOR,
            autopilot=mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA,
            base_mode=0, custom_mode=0,
            system_status=mavutil.mavlink.MAV_STATE_ACTIVE
        )
        sock.sendall(hb.pack(mav))

        # Sahte cevabi oku
        sock.settimeout(1.0)
        data = sock.recv(1024)
        sock.close()

        # Parse response
        resp_mav = mavutil.mavlink.MAVLink(None)
        resp_mav.robust_parsing = True
        msgs = resp_mav.parse_buffer(data)
        self.assertTrue(len(msgs) > 0)
        self.assertEqual(msgs[0].get_type(), "HEARTBEAT")

        # events.json'daki kaydi kontrol et
        time.sleep(0.1)
        events = _read_events()
        tcp_events = [e for e in events if e.get("protocol") == "TCP" and e.get("source_port") == client_port]
        self.assertTrue(len(tcp_events) >= 1)
        self.assertEqual(tcp_events[-1]["message_type"], "HEARTBEAT")
        self.assertEqual(tcp_events[-1]["status"], "NORMAL")
        self.assertEqual(tcp_events[-1]["protocol"], "TCP")
        self.assertNotEqual(tcp_events[-1]["source_port"], TEST_TCP_PORT)

    def test_tcp_param_set_suspicious(self):
        """TCP uzerinden PARAM_SET gonderilmeli ve status SUSPIC olmali"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", TEST_TCP_PORT))
        client_port = sock.getsockname()[1]

        mav = self._create_mav()
        pset = mav.param_set_encode(
            target_system=1, target_component=1,
            param_id=b"TCP_TEST_P\x00\x00\x00\x00\x00\x00",
            param_value=55.0,
            param_type=mavutil.mavlink.MAV_PARAM_TYPE_REAL32
        )
        sock.sendall(pset.pack(mav))

        # Sahte cevabi oku (PARAM_VALUE)
        sock.settimeout(1.0)
        data = sock.recv(1024)
        sock.close()

        resp_mav = mavutil.mavlink.MAVLink(None)
        resp_mav.robust_parsing = True
        msgs = resp_mav.parse_buffer(data)
        self.assertTrue(len(msgs) > 0)
        self.assertEqual(msgs[0].get_type(), "PARAM_VALUE")

        time.sleep(0.1)
        events = _read_events()
        tcp_events = [e for e in events if e.get("protocol") == "TCP" and e.get("source_port") == client_port]
        self.assertTrue(len(tcp_events) >= 1)
        self.assertEqual(tcp_events[-1]["message_type"], "PARAM_SET")
        self.assertEqual(tcp_events[-1]["status"], "SUSPIC")

    def test_tcp_invalid_data_does_not_crash(self):
        """TCP uzerinden gecersiz metin gonderildiginde server cokmemeli"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", TEST_TCP_PORT))
        client_port = sock.getsockname()[1]

        sock.sendall(b"HELLO MAVLINK")
        sock.close()

        time.sleep(0.1)
        events = _read_events()
        tcp_events = [e for e in events if e.get("protocol") == "TCP" and e.get("source_port") == client_port]
        self.assertTrue(len(tcp_events) >= 1)
        self.assertEqual(tcp_events[-1]["message_type"], "UNKNOWN")
        self.assertEqual(tcp_events[-1]["status"], "NORMAL")

    def test_tcp_command_long_suspicious(self):
        """TCP uzerinden COMMAND_LONG gonderilmeli ve status SUSPIC olmali"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", TEST_TCP_PORT))
        client_port = sock.getsockname()[1]

        mav = self._create_mav()
        cmd = mav.command_long_encode(
            target_system=1, target_component=1,
            command=mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM,
            confirmation=0,
            param1=1, param2=0, param3=0, param4=0,
            param5=0, param6=0, param7=0
        )
        sock.sendall(cmd.pack(mav))

        # Sahte cevabi oku (COMMAND_ACK)
        sock.settimeout(1.0)
        data = sock.recv(1024)
        sock.close()

        resp_mav = mavutil.mavlink.MAVLink(None)
        resp_mav.robust_parsing = True
        msgs = resp_mav.parse_buffer(data)
        self.assertTrue(len(msgs) > 0)
        self.assertEqual(msgs[0].get_type(), "COMMAND_ACK")

        time.sleep(0.1)
        events = _read_events()
        tcp_events = [e for e in events if e.get("protocol") == "TCP" and e.get("source_port") == client_port]
        self.assertTrue(len(tcp_events) >= 1)
        self.assertEqual(tcp_events[-1]["message_type"], "COMMAND_LONG")
        self.assertEqual(tcp_events[-1]["status"], "SUSPIC")

    def test_tcp_multiple_clients(self):
        """En az iki TCP client ayni anda baglanmali, birbirini etkilememeli"""
        results = []

        def tcp_client(client_id, msg_type):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("127.0.0.1", TEST_TCP_PORT))
            port = s.getsockname()[1]
            mav = self._create_mav()

            if msg_type == "HEARTBEAT":
                msg = mav.heartbeat_encode(
                    type=mavutil.mavlink.MAV_TYPE_QUADROTOR,
                    autopilot=mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA,
                    base_mode=0, custom_mode=0,
                    system_status=mavutil.mavlink.MAV_STATE_ACTIVE
                )
                expected_status = "NORMAL"
            else:
                msg = mav.param_set_encode(
                    target_system=1, target_component=1,
                    param_id=b"MULTI_TCP\x00\x00\x00\x00\x00\x00\x00",
                    param_value=10.0,
                    param_type=mavutil.mavlink.MAV_PARAM_TYPE_REAL32
                )
                expected_status = "SUSPIC"

            s.sendall(msg.pack(mav))
            time.sleep(0.15)
            s.close()
            results.append((client_id, port, msg_type, expected_status))

        t1 = threading.Thread(target=tcp_client, args=("X", "HEARTBEAT"))
        t2 = threading.Thread(target=tcp_client, args=("Y", "PARAM_SET"))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        time.sleep(0.2)
        events = _read_events()

        for cid, port, mtype, expected in results:
            matching = [e for e in events if e["source_port"] == port and e["protocol"] == "TCP"]
            self.assertTrue(len(matching) >= 1, f"TCP Client {cid} (port {port}) kaydedilmemis")
            self.assertEqual(matching[-1]["message_type"], mtype)
            self.assertEqual(matching[-1]["status"], expected)


if __name__ == "__main__":
    unittest.main()

