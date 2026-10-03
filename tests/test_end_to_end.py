# test_end_to_end.py
# Asama 10: Kapsamli End-to-End, Stabilite, Coklu Istemci ve Yuk Testleri

import sys
import os
import time
import json
import socket
import threading
import unittest
from pymavlink import mavutil

# Kok dizini python path'ine ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from server import main as run_udp_server
from tcp_server import run_tcp_server
from event_logger import _read_events
from event_validator import validate_event_with_reason
from behavior_analyzer import clear_history

UDP_PORT = 14550
TCP_PORT = 14551


def create_mav():
    return mavutil.mavlink.MAVLink(None, srcSystem=1, srcComponent=1)


class TestMAVLinkHoneypotEndToEnd(unittest.TestCase):
    """
    Asama 10: UDP + TCP + Parser + Classifier + Behavior + Validator + Logger Birlikte Testi
    """

    @classmethod
    def setUpClass(cls):
        clear_history()
        # UDP ve TCP sunucularini ayri arka plan thread'lerinde baslat
        cls.stop_tcp_event = threading.Event()

        # UDP Server thread
        cls.udp_thread = threading.Thread(target=run_udp_server, daemon=True)
        cls.udp_thread.start()

        # TCP Server thread
        cls.tcp_thread = threading.Thread(
            target=run_tcp_server,
            kwargs={"host": "127.0.0.1", "port": TCP_PORT, "stop_event": cls.stop_tcp_event},
            daemon=True
        )
        cls.tcp_thread.start()

        time.sleep(0.5)  # Sunucularin hazir olmasini bekle

    def setUp(self):
        clear_history()

    @classmethod
    def tearDownClass(cls):
        cls.stop_tcp_event.set()
        time.sleep(0.2)

    # -------------------------------------------------------------
    # 10.1 NORMAL SENARYO (UDP)
    # -------------------------------------------------------------
    def test_01_normal_scenario_udp(self):
        """HEARTBEAT, SYS_STATUS, ATTITUDE, GLOBAL_POSITION_INT -> Hepsi NORMAL olmali"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        client_port = sock.getsockname()[1]
        mav = create_mav()

        # 1. HEARTBEAT
        hb = mav.heartbeat_encode(
            type=mavutil.mavlink.MAV_TYPE_QUADROTOR,
            autopilot=mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA,
            base_mode=0, custom_mode=0,
            system_status=mavutil.mavlink.MAV_STATE_ACTIVE
        )
        sock.sendto(hb.pack(mav), ("127.0.0.1", UDP_PORT))
        time.sleep(0.05)

        # 2. SYS_STATUS
        sys_stat = mav.sys_status_encode(0, 0, 0, 500, 12000, 100, 75, 0, 0, 0, 0, 0, 0)
        sock.sendto(sys_stat.pack(mav), ("127.0.0.1", UDP_PORT))
        time.sleep(0.05)

        # 3. ATTITUDE
        att = mav.attitude_encode(1000, 0.1, 0.2, 0.3, 0.0, 0.0, 0.0)
        sock.sendto(att.pack(mav), ("127.0.0.1", UDP_PORT))
        time.sleep(0.05)

        # 4. GLOBAL_POSITION_INT
        pos = mav.global_position_int_encode(2000, 390000000, 320000000, 50000, 50000, 0, 0, 0, 18000)
        sock.sendto(pos.pack(mav), ("127.0.0.1", UDP_PORT))
        time.sleep(0.1)
        sock.close()

        events = _read_events()
        matching_events = [e for e in events if e["source_port"] == client_port]
        self.assertEqual(len(matching_events), 4)
        for e in matching_events:
            self.assertEqual(e["status"], "NORMAL", f"{e['message_type']} NORMAL olmaliydi")

    # -------------------------------------------------------------
    # 10.2 SUSPICIOUS SENARYO (UDP)
    # -------------------------------------------------------------
    def test_02_suspicious_scenario_udp(self):
        """PARAM_REQUEST_LIST, PARAM_SET, COMMAND_LONG -> Hepsi SUSPIC olmali"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        client_port = sock.getsockname()[1]
        mav = create_mav()

        # 1. PARAM_REQUEST_LIST
        pr = mav.param_request_list_encode(target_system=1, target_component=1)
        sock.sendto(pr.pack(mav), ("127.0.0.1", UDP_PORT))
        time.sleep(0.05)

        # 2. PARAM_SET
        ps = mav.param_set_encode(1, 1, b"SYS_ID\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 2.0, mavutil.mavlink.MAV_PARAM_TYPE_REAL32)
        sock.sendto(ps.pack(mav), ("127.0.0.1", UDP_PORT))
        time.sleep(0.05)

        # 3. COMMAND_LONG
        cmd = mav.command_long_encode(1, 1, mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM, 0, 1, 0, 0, 0, 0, 0, 0)
        sock.sendto(cmd.pack(mav), ("127.0.0.1", UDP_PORT))
        time.sleep(0.1)
        sock.close()

        events = _read_events()
        matching = [e for e in events if e["source_port"] == client_port]
        self.assertEqual(len(matching), 3)
        for e in matching:
            self.assertEqual(e["status"], "SUSPIC", f"{e['message_type']} SUSPIC olmaliydi")

    # -------------------------------------------------------------
    # 10.2b SUSPICIOUS SENARYO (TCP)
    # -------------------------------------------------------------
    def test_02b_suspicious_scenario_tcp(self):
        """TCP: PARAM_SET, COMMAND_LONG -> Hepsi SUSPIC olmali"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", TCP_PORT))
        client_port = sock.getsockname()[1]
        mav = create_mav()

        # 1. PARAM_SET
        ps = mav.param_set_encode(1, 1, b"TCP_SUSP\x00\x00\x00\x00\x00\x00\x00\x00", 5.0, mavutil.mavlink.MAV_PARAM_TYPE_REAL32)
        sock.sendall(ps.pack(mav))
        time.sleep(0.1)

        # 2. COMMAND_LONG
        cmd = mav.command_long_encode(1, 1, mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM, 0, 1, 0, 0, 0, 0, 0, 0)
        sock.sendall(cmd.pack(mav))
        time.sleep(0.1)
        sock.close()

        events = _read_events()
        matching = [e for e in events if e["source_port"] == client_port and e["protocol"] == "TCP"]
        self.assertEqual(len(matching), 2)
        for e in matching:
            self.assertEqual(e["status"], "SUSPIC", f"TCP {e['message_type']} SUSPIC olmaliydi")

    # -------------------------------------------------------------
    # 10.3 BEHAVIOR ATTACK (BURST) SENARYOSU
    # -------------------------------------------------------------
    def test_03_behavior_burst_attack(self):
        """Hizlica 12 HEARTBEAT gonderildiginde esik asilip sonrakiler SUSPIC olmali"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        mav = create_mav()
        hb = mav.heartbeat_encode(
            type=mavutil.mavlink.MAV_TYPE_QUADROTOR,
            autopilot=mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA,
            base_mode=0, custom_mode=0,
            system_status=mavutil.mavlink.MAV_STATE_ACTIVE
        )
        msg_bytes = hb.pack(mav)

        for _ in range(12):
            sock.sendto(msg_bytes, ("127.0.0.1", UDP_PORT))
            time.sleep(0.02)

        time.sleep(0.2)
        sock.close()

        events = _read_events()
        # Son 12 event icerisinde SUSPIC durumuna gecen HEARTBEAT bulunmali
        recent_hb = [e for e in events[-15:] if e["message_type"] == "HEARTBEAT"]
        self.assertTrue(any(e["status"] == "SUSPIC" for e in recent_hb), "Burst sonrasi HEARTBEAT SUSPIC olmaliydi")

    # -------------------------------------------------------------
    # 10.3 INVALID DATA TEST (UDP + TCP)
    # -------------------------------------------------------------
    def test_03b_invalid_data_udp_tcp(self):
        """UDP ve TCP uzerinden HELLO MAVLINK ve random byte gonder, server cokmemeli"""
        # UDP bozuk veri
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.sendto(b"HELLO MAVLINK", ("127.0.0.1", UDP_PORT))
        udp_sock.sendto(b"\x00\x01\x02\xff\xfe", ("127.0.0.1", UDP_PORT))
        udp_sock.close()

        # TCP bozuk veri
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_sock.connect(("127.0.0.1", TCP_PORT))
        tcp_sock.sendall(b"HELLO MAVLINK")
        tcp_sock.sendall(b"\xff\x00\xaa\xbb")
        tcp_sock.close()

        time.sleep(0.2)

        # Recovery testi: Sunucu hala ayakta mi? Yeni HEARTBEAT gonder
        rec_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rec_sock.bind(("127.0.0.1", 0))
        rec_port = rec_sock.getsockname()[1]
        mav = create_mav()
        hb = mav.heartbeat_encode(
            type=mavutil.mavlink.MAV_TYPE_QUADROTOR,
            autopilot=mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA,
            base_mode=0, custom_mode=0,
            system_status=mavutil.mavlink.MAV_STATE_ACTIVE
        )
        rec_sock.sendto(hb.pack(mav), ("127.0.0.1", UDP_PORT))
        time.sleep(0.2)
        rec_sock.close()

        events = _read_events()
        rec_events = [e for e in events if e["source_port"] == rec_port and e["message_type"] == "HEARTBEAT"]
        self.assertTrue(len(rec_events) >= 1, "Server invalid data sonrasi yeni HEARTBEAT'i basariyla kaydetmeli")

        # JSON bozulmadi mi?
        self.assertIsInstance(events, list)

    # -------------------------------------------------------------
    # 10.4 DUPLICATE EVENT TESTİ
    # -------------------------------------------------------------
    def test_04_duplicate_events_not_dropped(self):
        """Ayni mesaj tek soketten 2 kez gonderildiginde 2 ayri event olusmali (Deduplication yok)"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        client_port = sock.getsockname()[1]
        mav = create_mav()
        hb = mav.heartbeat_encode(
            type=mavutil.mavlink.MAV_TYPE_QUADROTOR,
            autopilot=mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA,
            base_mode=0, custom_mode=0,
            system_status=mavutil.mavlink.MAV_STATE_ACTIVE
        )
        msg_bytes = hb.pack(mav)

        # 1. gonderim
        sock.sendto(msg_bytes, ("127.0.0.1", UDP_PORT))
        time.sleep(0.05)
        # 2. gonderim
        sock.sendto(msg_bytes, ("127.0.0.1", UDP_PORT))
        time.sleep(0.1)
        sock.close()

        events = _read_events()
        dup_events = [e for e in events if e["source_port"] == client_port and e["message_type"] == "HEARTBEAT"]
        self.assertEqual(len(dup_events), 2, "Ayni porttan gelen 2 duplicate mesaj icin tam 2 event kaydedilmeliydi")

    # -------------------------------------------------------------
    # 10.5 SOURCE PORT TESTİ (14550 ve 14551 Asla Kaydedilmemeli)
    # -------------------------------------------------------------
    def test_05_source_port_never_server_port(self):
        """events.json icerisindeki hicbir event'in source_port'u sunucu portu (14550, 14551) olmamali"""
        events = _read_events()
        for e in events:
            self.assertNotEqual(e["source_port"], 14550, "14550 UDP server portu source_port olarak yazilmis!")
            self.assertNotEqual(e["source_port"], 14551, "14551 TCP server portu source_port olarak yazilmis!")
            self.assertIsInstance(e["source_port"], int)

    # -------------------------------------------------------------
    # 10.5b TCP SOURCE PORT TESTİ
    # -------------------------------------------------------------
    def test_05b_tcp_source_port_is_client_port(self):
        """TCP event'lerinde source_port client'in gercek ephemeral portu olmali"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", TCP_PORT))
        client_port = sock.getsockname()[1]
        mav = create_mav()
        hb = mav.heartbeat_encode(
            type=mavutil.mavlink.MAV_TYPE_QUADROTOR,
            autopilot=mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA,
            base_mode=0, custom_mode=0,
            system_status=mavutil.mavlink.MAV_STATE_ACTIVE
        )
        sock.sendall(hb.pack(mav))
        time.sleep(0.15)
        sock.close()

        events = _read_events()
        tcp_events = [e for e in events if e["source_port"] == client_port and e["protocol"] == "TCP"]
        self.assertTrue(len(tcp_events) >= 1, "TCP client portu dogru kaydedilmemis")
        self.assertNotEqual(tcp_events[0]["source_port"], 14551, "source_port server portu olmamali")

    # -------------------------------------------------------------
    # 10.6 JSON INTEGRITY & EVENT SCHEMA TESTİ
    # -------------------------------------------------------------
    def test_06_json_integrity_and_schema(self):
        """events.json dosyasindaki her event kesin olarak 6 alana ve gecerli degerlere sahip olmali"""
        events = _read_events()
        self.assertIsInstance(events, list, "Root JSON objesi liste (array) olmalidir")
        self.assertTrue(len(events) > 0, "events.json bos olmamalidir")

        expected_keys = {
            "timestamp",
            "source_ip",
            "source_port",
            "protocol",
            "message_type",
            "status"
        }

        for i, event in enumerate(events):
            self.assertIsInstance(event, dict, f"Event #{i} dict olmalidir")
            self.assertEqual(set(event.keys()), expected_keys, f"Event #{i} tam 6 alana sahip olmalidir: {event}")
            self.assertIn(event["protocol"], {"UDP", "TCP"}, f"Event #{i} protocol gecersiz")
            self.assertIn(event["status"], {"NORMAL", "SUSPIC"}, f"Event #{i} status gecersiz")
            self.assertIsInstance(event["source_port"], int, f"Event #{i} source_port integer olmali")
            self.assertIsInstance(event["timestamp"], str, f"Event #{i} timestamp string olmali")
            is_valid, reason = validate_event_with_reason(event)
            self.assertTrue(is_valid, f"Event #{i} validator tarafindan reddedildi: {reason}")

    # -------------------------------------------------------------
    # 10.7 RESPONDER TESTİ (End-to-End)
    # -------------------------------------------------------------
    def test_07_responder_end_to_end(self):
        """HEARTBEAT, PARAM_REQUEST_LIST, PARAM_SET, COMMAND_LONG icin sahte cevap donmeli"""
        mav = create_mav()

        # HEARTBEAT -> HEARTBEAT cevap
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        hb = mav.heartbeat_encode(
            type=mavutil.mavlink.MAV_TYPE_QUADROTOR,
            autopilot=mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA,
            base_mode=0, custom_mode=0,
            system_status=mavutil.mavlink.MAV_STATE_ACTIVE
        )
        sock.sendto(hb.pack(mav), ("127.0.0.1", UDP_PORT))
        data, _ = sock.recvfrom(1024)
        resp_mav = mavutil.mavlink.MAVLink(None)
        resp_mav.robust_parsing = True
        msgs = resp_mav.parse_buffer(data)
        self.assertTrue(len(msgs) > 0)
        self.assertEqual(msgs[0].get_type(), "HEARTBEAT")
        sock.close()

        time.sleep(0.05)

        # PARAM_REQUEST_LIST -> PARAM_VALUE cevap
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock2.settimeout(1.0)
        pr = mav.param_request_list_encode(target_system=1, target_component=1)
        sock2.sendto(pr.pack(mav), ("127.0.0.1", UDP_PORT))
        data2, _ = sock2.recvfrom(1024)
        msgs2 = resp_mav.parse_buffer(data2)
        self.assertTrue(len(msgs2) > 0)
        self.assertEqual(msgs2[0].get_type(), "PARAM_VALUE")
        sock2.close()

        time.sleep(0.05)

        # PARAM_SET -> PARAM_VALUE onay
        sock3 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock3.settimeout(1.0)
        ps = mav.param_set_encode(1, 1, b"RESP_TEST\x00\x00\x00\x00\x00\x00\x00", 1.0, mavutil.mavlink.MAV_PARAM_TYPE_REAL32)
        sock3.sendto(ps.pack(mav), ("127.0.0.1", UDP_PORT))
        data3, _ = sock3.recvfrom(1024)
        msgs3 = resp_mav.parse_buffer(data3)
        self.assertTrue(len(msgs3) > 0)
        self.assertEqual(msgs3[0].get_type(), "PARAM_VALUE")
        sock3.close()

        time.sleep(0.05)

        # COMMAND_LONG -> COMMAND_ACK cevap
        sock4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock4.settimeout(1.0)
        cmd = mav.command_long_encode(1, 1, mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM, 0, 1, 0, 0, 0, 0, 0, 0)
        sock4.sendto(cmd.pack(mav), ("127.0.0.1", UDP_PORT))
        data4, _ = sock4.recvfrom(1024)
        msgs4 = resp_mav.parse_buffer(data4)
        self.assertTrue(len(msgs4) > 0)
        self.assertEqual(msgs4[0].get_type(), "COMMAND_ACK")
        sock4.close()

    # -------------------------------------------------------------
    # 10.8 MULTI CLIENT TEST (UDP A, UDP B, TCP C, TCP D)
    # -------------------------------------------------------------
    def test_08_multi_client_concurrent_udp_tcp(self):
        """Ayni anda Client A (UDP), Client B (UDP), Client C (TCP), Client D (TCP) calismali"""
        results = []

        def client_udp(client_id, msg_type):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
            mav = create_mav()
            hb = mav.heartbeat_encode(
                type=mavutil.mavlink.MAV_TYPE_QUADROTOR,
                autopilot=mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA,
                base_mode=0, custom_mode=0,
                system_status=mavutil.mavlink.MAV_STATE_ACTIVE
            )
            s.sendto(hb.pack(mav), ("127.0.0.1", UDP_PORT))
            time.sleep(0.1)
            s.close()
            results.append((client_id, "UDP", port))

        def client_tcp(client_id, msg_type):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("127.0.0.1", TCP_PORT))
            port = s.getsockname()[1]
            mav = create_mav()
            hb = mav.heartbeat_encode(
                type=mavutil.mavlink.MAV_TYPE_QUADROTOR,
                autopilot=mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA,
                base_mode=0, custom_mode=0,
                system_status=mavutil.mavlink.MAV_STATE_ACTIVE
            )
            s.sendall(hb.pack(mav))
            time.sleep(0.1)
            s.close()
            results.append((client_id, "TCP", port))

        t_a = threading.Thread(target=client_udp, args=("A", "HEARTBEAT"))
        t_b = threading.Thread(target=client_udp, args=("B", "HEARTBEAT"))
        t_c = threading.Thread(target=client_tcp, args=("C", "HEARTBEAT"))
        t_d = threading.Thread(target=client_tcp, args=("D", "HEARTBEAT"))

        for t in [t_a, t_b, t_c, t_d]:
            t.start()
        for t in [t_a, t_b, t_c, t_d]:
            t.join()

        time.sleep(0.3)
        events = _read_events()

        # 4 client portunun da events.json icinde var oldugunu kontrol et
        for cid, proto, port in results:
            matching = [e for e in events if e["source_port"] == port and e["protocol"] == proto]
            self.assertTrue(len(matching) >= 1, f"Client {cid} ({proto}:{port}) kaydedilmemis")

        # events.json icinde hem UDP hem TCP protokol bulunmali
        protocols = set(e["protocol"] for e in events)
        self.assertIn("UDP", protocols, "events.json icinde UDP event olmali")
        self.assertIn("TCP", protocols, "events.json icinde TCP event olmali")

    # -------------------------------------------------------------
    # 10.9 REGRESSION TEST
    # -------------------------------------------------------------
    def test_09_regression_all_components(self):
        """Onceki tum ozelliklerin calismaya devam ettigini dogrular"""
        mav = create_mav()

        # 1. UDP 14550 calisiyor mu?
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        udp_port = sock.getsockname()[1]
        hb = mav.heartbeat_encode(
            type=mavutil.mavlink.MAV_TYPE_QUADROTOR,
            autopilot=mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA,
            base_mode=0, custom_mode=0,
            system_status=mavutil.mavlink.MAV_STATE_ACTIVE
        )
        sock.sendto(hb.pack(mav), ("127.0.0.1", UDP_PORT))
        time.sleep(0.1)
        sock.close()

        events = _read_events()
        udp_events = [e for e in events if e["source_port"] == udp_port]
        self.assertTrue(len(udp_events) >= 1, "UDP server calismali")
        self.assertEqual(udp_events[-1]["message_type"], "HEARTBEAT")
        self.assertEqual(udp_events[-1]["status"], "NORMAL")
        self.assertEqual(udp_events[-1]["protocol"], "UDP")

        # 2. TCP calisiyor mu?
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_sock.connect(("127.0.0.1", TCP_PORT))
        tcp_port = tcp_sock.getsockname()[1]
        tcp_sock.sendall(hb.pack(mav))
        time.sleep(0.1)
        tcp_sock.close()

        events = _read_events()
        tcp_events = [e for e in events if e["source_port"] == tcp_port]
        self.assertTrue(len(tcp_events) >= 1, "TCP server calismali")
        self.assertEqual(tcp_events[-1]["message_type"], "HEARTBEAT")
        self.assertEqual(tcp_events[-1]["protocol"], "TCP")

        # 3. Classifier calisiyor mu? (PARAM_SET -> SUSPIC)
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock2.bind(("127.0.0.1", 0))
        p2 = sock2.getsockname()[1]
        ps = mav.param_set_encode(1, 1, b"REG_TEST\x00\x00\x00\x00\x00\x00\x00\x00", 1.0, mavutil.mavlink.MAV_PARAM_TYPE_REAL32)
        sock2.sendto(ps.pack(mav), ("127.0.0.1", UDP_PORT))
        time.sleep(0.1)
        sock2.close()

        events = _read_events()
        reg = [e for e in events if e["source_port"] == p2]
        self.assertTrue(len(reg) >= 1, "Classifier calismali")
        self.assertEqual(reg[-1]["status"], "SUSPIC")

        # 4. event_validator calisiyor mu? (events.json'daki her event gecerli mi)
        for e in events[-5:]:
            is_valid, reason = validate_event_with_reason(e)
            self.assertTrue(is_valid, f"Regression: Validator hatasi: {reason}")

    # -------------------------------------------------------------
    # 10.10 PERFORMANS / YUK TESTI (50 MAVLink Mesaji)
    # -------------------------------------------------------------
    def test_10_performance_load_test(self):
        """Kisa surede 50 MAVLink mesaji gonderildiginde server crash olmamali, hepsi yazilmali"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        mav = create_mav()
        hb = mav.heartbeat_encode(
            type=mavutil.mavlink.MAV_TYPE_QUADROTOR,
            autopilot=mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA,
            base_mode=0, custom_mode=0,
            system_status=mavutil.mavlink.MAV_STATE_ACTIVE
        )
        msg_bytes = hb.pack(mav)

        # 50 mesaj gonder
        for _ in range(50):
            sock.sendto(msg_bytes, ("127.0.0.1", UDP_PORT))
            time.sleep(0.005)

        time.sleep(0.5)
        sock.close()

        events = _read_events()
        load_events = [e for e in events if e["source_port"] == port]
        self.assertEqual(len(load_events), 50, "50 mesajin tamami events.json dosyasina yazilmis olmali")


if __name__ == "__main__":
    unittest.main()
