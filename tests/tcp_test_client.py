# tcp_test_client.py
# MAVLink Honeypot - TCP Test Client
# Asama 9: TCP Uzerinden MAVLink Mesajlari ve Coklu Istemci Testleri

import socket
import time
import threading
from pymavlink import mavutil

HOST = "127.0.0.1"
PORT = 14551
RESPONSE_TIMEOUT = 1.0


def create_mav():
    """Test icin MAVLink nesnesi olusturur"""
    return mavutil.mavlink.MAVLink(None, srcSystem=1, srcComponent=1)


def wait_for_tcp_response(sock):
    """Honeypot TCP sunucusundan donen cevabi bekler ve parse eder"""
    try:
        sock.settimeout(RESPONSE_TIMEOUT)
        data = sock.recv(1024)
        if not data:
            print("  << TCP baglantisi kapandi.")
            return None

        mav = mavutil.mavlink.MAVLink(None)
        mav.robust_parsing = True
        messages = mav.parse_buffer(data)

        if messages and len(messages) > 0:
            response = messages[0]
            msg_type = response.get_type()
            if msg_type != "BAD_DATA":
                print(f"  << TCP Honeypot cevabi: {msg_type}")
                return msg_type
        print("  << TCP Honeypot cevabi: (parse edilemedi)")
        return None
    except socket.timeout:
        print("  << TCP Honeypot cevap vermedi (timeout).")
        return None
    except Exception as e:
        print(f"  << TCP Honeypot cevap alma hatasi: {e}")
        return None


def run_single_client_sequence():
    """
    Tek bir TCP baglantisi acip sirasiyla:
    1. HEARTBEAT (NORMAL)
    2. ATTITUDE (NORMAL)
    3. PARAM_SET (SUSPIC)
    4. COMMAND_LONG (SUSPIC)
    5. HELLO MAVLINK (Gecersiz veri)
    6. Rastgele byte (Bozuk veri)
    gonderir ve baglantiyi kapatir.
    """
    print("\n--- Tekil TCP Istemci Testi Baslatiliyor ---")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((HOST, PORT))
        local_port = sock.getsockname()[1]
        print(f"  TCP baglantisi kuruldu. Yerel Port (source_port): {local_port}")

        mav = create_mav()

        # 1. HEARTBEAT
        hb = mav.heartbeat_encode(
            type=mavutil.mavlink.MAV_TYPE_QUADROTOR,
            autopilot=mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA,
            base_mode=0, custom_mode=0,
            system_status=mavutil.mavlink.MAV_STATE_ACTIVE
        )
        sock.sendall(hb.pack(mav))
        print("[NORMAL]   [TCP] HEARTBEAT gonderildi.")
        wait_for_tcp_response(sock)
        time.sleep(0.1)

        # 2. ATTITUDE
        att = mav.attitude_encode(
            time_boot_ms=1000,
            roll=0.1, pitch=0.2, yaw=0.3,
            rollspeed=0.0, pitchspeed=0.0, yawspeed=0.0
        )
        sock.sendall(att.pack(mav))
        print("[NORMAL]   [TCP] ATTITUDE gonderildi.")
        time.sleep(0.1)

        # 3. PARAM_SET
        pset = mav.param_set_encode(
            target_system=1, target_component=1,
            param_id=b"TCP_PARAM\x00\x00\x00\x00\x00\x00\x00",
            param_value=42.0,
            param_type=mavutil.mavlink.MAV_PARAM_TYPE_REAL32
        )
        sock.sendall(pset.pack(mav))
        print("[SUSPIC]   [TCP] PARAM_SET gonderildi.")
        wait_for_tcp_response(sock)
        time.sleep(0.1)

        # 4. COMMAND_LONG
        cmd = mav.command_long_encode(
            target_system=1, target_component=1,
            command=mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM,
            confirmation=0,
            param1=1, param2=0, param3=0, param4=0,
            param5=0, param6=0, param7=0
        )
        sock.sendall(cmd.pack(mav))
        print("[SUSPIC]   [TCP] COMMAND_LONG gonderildi.")
        wait_for_tcp_response(sock)
        time.sleep(0.1)

        # 5. Invalid Data: HELLO MAVLINK
        sock.sendall(b"HELLO MAVLINK")
        print("[UNKNOWN]  [TCP] HELLO MAVLINK gonderildi. (gecersiz veri)")
        time.sleep(0.1)

        # 6. Corrupt Data: Random bytes
        sock.sendall(b"\x00\xff\xfe\xfd\x01\x02")
        print("[UNKNOWN]  [TCP] Rastgele byte verisi gonderildi. (bozuk veri)")
        time.sleep(0.1)

    finally:
        sock.close()
        print("  TCP baglantisi duzgun sekilde kapatildi.\n")


def run_multi_client_concurrent():
    """
    Ayni anda iki farkli TCP istemci baglantisi acar ve mesaj gonderir (Concurrency Test).
    """
    print("\n--- Coklu TCP Istemci Testi (Es zamanli 2 Client) ---")

    def client_worker(client_id, message_type):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((HOST, PORT))
            port = s.getsockname()[1]
            print(f"  [Client {client_id}] Baglandi. Port: {port}")
            mav = create_mav()

            if message_type == "HEARTBEAT":
                msg = mav.heartbeat_encode(
                    type=mavutil.mavlink.MAV_TYPE_QUADROTOR,
                    autopilot=mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA,
                    base_mode=0, custom_mode=0,
                    system_status=mavutil.mavlink.MAV_STATE_ACTIVE
                )
                s.sendall(msg.pack(mav))
                print(f"  [Client {client_id}] HEARTBEAT gonderdi.")
                wait_for_tcp_response(s)
            elif message_type == "PARAM_SET":
                msg = mav.param_set_encode(
                    target_system=1, target_component=1,
                    param_id=b"MULTI_TCP\x00\x00\x00\x00\x00\x00\x00",
                    param_value=10.0,
                    param_type=mavutil.mavlink.MAV_PARAM_TYPE_REAL32
                )
                s.sendall(msg.pack(mav))
                print(f"  [Client {client_id}] PARAM_SET gonderdi.")
                wait_for_tcp_response(s)

            time.sleep(0.2)
        finally:
            s.close()
            print(f"  [Client {client_id}] Baglanti kapandi.")

    t1 = threading.Thread(target=client_worker, args=("A", "HEARTBEAT"))
    t2 = threading.Thread(target=client_worker, args=("B", "PARAM_SET"))

    t1.start()
    t2.start()

    t1.join()
    t2.join()
    print("  Coklu TCP istemci testi tamamlandi.\n")


def main():
    print("=" * 55)
    print("  MAVLink Honeypot - TCP Test Paketi (Asama 9)")
    print("=" * 55)

    run_single_client_sequence()
    time.sleep(0.5)
    run_multi_client_concurrent()

    print("=" * 55)
    print("  Tum TCP testleri tamamlandi.")
    print("=" * 55)


if __name__ == "__main__":
    main()
