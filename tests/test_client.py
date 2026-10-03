# test_client.py
# MAVLink Honeypot - Kapsamli Test Client
# Asama 8: Tum asamalari, stabiliteyi ve davranissal analizi test eder
#
# Testler:
#   1. HEARTBEAT           (NORMAL)
#   2. ATTITUDE            (NORMAL)
#   3. SYS_STATUS          (NORMAL)
#   4. GLOBAL_POSITION_INT (NORMAL)
#   5. PARAM_REQUEST_LIST  (SUSPIC)
#   6. PARAM_SET           (SUSPIC)
#   7. COMMAND_LONG        (SUSPIC)
#   8. HELLO MAVLINK       (UNKNOWN - gecersiz veri)
#   9. Rastgele byte       (UNKNOWN - bozuk veri)
#  10. Duplicate HEARTBEAT (ayni mesaj 2 kez)
#  11. Multi-client        (2 farkli kaynak port)

import socket
import time
from pymavlink import mavutil

HOST = "127.0.0.1"
PORT = 14550

# Cevap bekleme suresi (saniye)
RESPONSE_TIMEOUT = 0.5


# ================================================
# YARDIMCI FONKSIYONLAR
# ================================================

def send_mavlink_message(mav, sock, msg):
    """MAVLink mesajini UDP uzerinden gonderir"""
    msg_bytes = msg.pack(mav)
    sock.sendto(msg_bytes, (HOST, PORT))


def wait_for_response(sock):
    """Honeypot'tan gelen sahte cevabi dinler"""
    try:
        sock.settimeout(RESPONSE_TIMEOUT)
        data, addr = sock.recvfrom(1024)

        mav = mavutil.mavlink.MAVLink(None)
        mav.robust_parsing = True
        messages = mav.parse_buffer(data)

        if messages and len(messages) > 0:
            response = messages[0]
            msg_type = response.get_type()
            if msg_type != "BAD_DATA":
                print(f"  << Honeypot cevabi: {msg_type}")
                return
        print("  << Honeypot cevabi: (parse edilemedi)")
    except socket.timeout:
        print("  << Honeypot cevap vermedi.")
    except Exception:
        print("  << Honeypot cevabi alinamadi.")


def create_mav():
    """Test icin MAVLink nesnesi olusturur"""
    return mavutil.mavlink.MAVLink(None, srcSystem=1, srcComponent=1)


# ================================================
# MAVLink MESAJ GONDERME FONKSIYONLARI
# ================================================

def send_heartbeat():
    """HEARTBEAT mesaji (Beklenen: NORMAL + sahte cevap)"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    mav = create_mav()

    msg = mav.heartbeat_encode(
        type=mavutil.mavlink.MAV_TYPE_QUADROTOR,
        autopilot=mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA,
        base_mode=0,
        custom_mode=0,
        system_status=mavutil.mavlink.MAV_STATE_ACTIVE
    )

    send_mavlink_message(mav, sock, msg)
    print("[NORMAL]   HEARTBEAT gonderildi.")
    wait_for_response(sock)
    sock.close()


def send_attitude():
    """ATTITUDE mesaji (Beklenen: NORMAL)"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    mav = create_mav()

    msg = mav.attitude_encode(
        time_boot_ms=1000,
        roll=0.1, pitch=0.2, yaw=0.3,
        rollspeed=0.0, pitchspeed=0.0, yawspeed=0.0
    )

    send_mavlink_message(mav, sock, msg)
    print("[NORMAL]   ATTITUDE gonderildi.")
    wait_for_response(sock)
    sock.close()


def send_sys_status():
    """SYS_STATUS mesaji (Beklenen: NORMAL)"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    mav = create_mav()

    msg = mav.sys_status_encode(
        onboard_control_sensors_present=0,
        onboard_control_sensors_enabled=0,
        onboard_control_sensors_health=0,
        load=500,
        voltage_battery=12000,
        current_battery=100,
        battery_remaining=75,
        drop_rate_comm=0,
        errors_comm=0,
        errors_count1=0,
        errors_count2=0,
        errors_count3=0,
        errors_count4=0
    )

    send_mavlink_message(mav, sock, msg)
    print("[NORMAL]   SYS_STATUS gonderildi.")
    wait_for_response(sock)
    sock.close()


def send_global_position_int():
    """GLOBAL_POSITION_INT mesaji (Beklenen: NORMAL)"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    mav = create_mav()

    msg = mav.global_position_int_encode(
        time_boot_ms=2000,
        lat=390000000,       # 39.0 derece
        lon=320000000,       # 32.0 derece
        alt=50000,           # 50 metre
        relative_alt=50000,
        vx=0, vy=0, vz=0,
        hdg=18000            # 180 derece
    )

    send_mavlink_message(mav, sock, msg)
    print("[NORMAL]   GLOBAL_POSITION_INT gonderildi.")
    wait_for_response(sock)
    sock.close()


def send_param_request_list():
    """PARAM_REQUEST_LIST mesaji (Beklenen: SUSPIC + sahte cevap)"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    mav = create_mav()

    msg = mav.param_request_list_encode(
        target_system=1,
        target_component=1
    )

    send_mavlink_message(mav, sock, msg)
    print("[SUSPIC]   PARAM_REQUEST_LIST gonderildi.")
    wait_for_response(sock)
    sock.close()


def send_param_set():
    """PARAM_SET mesaji (Beklenen: SUSPIC + sahte cevap)"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    mav = create_mav()

    msg = mav.param_set_encode(
        target_system=1,
        target_component=1,
        param_id=b"WP_RADIUS\x00\x00\x00\x00\x00\x00\x00",
        param_value=100.0,
        param_type=mavutil.mavlink.MAV_PARAM_TYPE_REAL32
    )

    send_mavlink_message(mav, sock, msg)
    print("[SUSPIC]   PARAM_SET gonderildi.")
    wait_for_response(sock)
    sock.close()


def send_command_long():
    """COMMAND_LONG mesaji (Beklenen: SUSPIC + sahte COMMAND_ACK)"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    mav = create_mav()

    msg = mav.command_long_encode(
        target_system=1,
        target_component=1,
        command=mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM,
        confirmation=0,
        param1=1, param2=0, param3=0, param4=0,
        param5=0, param6=0, param7=0
    )

    send_mavlink_message(mav, sock, msg)
    print("[SUSPIC]   COMMAND_LONG gonderildi. (ARM komutu)")
    wait_for_response(sock)
    sock.close()


# ================================================
# OZEL TEST FONKSIYONLARI
# ================================================

def send_hello():
    """Gecersiz duz metin verisi (Beklenen: UNKNOWN, NORMAL)"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(b"HELLO MAVLINK", (HOST, PORT))
    print("[UNKNOWN]  HELLO MAVLINK gonderildi. (gecersiz veri)")
    wait_for_response(sock)
    sock.close()


def send_random_bytes():
    """Rastgele/bozuk byte verisi (Beklenen: UNKNOWN, server cokmemeli)"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(b"\x00\x01\x02\x03\xff\xfe\xfd", (HOST, PORT))
    print("[UNKNOWN]  Rastgele byte verisi gonderildi. (bozuk veri)")
    wait_for_response(sock)
    sock.close()


def send_duplicate_heartbeat():
    """Ayni HEARTBEAT mesajini 2 kez gonderir (2 ayri event olmali)"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    mav = create_mav()

    msg = mav.heartbeat_encode(
        type=mavutil.mavlink.MAV_TYPE_QUADROTOR,
        autopilot=mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA,
        base_mode=0,
        custom_mode=0,
        system_status=mavutil.mavlink.MAV_STATE_ACTIVE
    )

    # Birinci gonderim
    send_mavlink_message(mav, sock, msg)
    print("[NORMAL]   HEARTBEAT #1 gonderildi. (duplicate test)")
    wait_for_response(sock)

    time.sleep(0.1)

    # Ikinci gonderim (ayni socket = ayni kaynak port)
    send_mavlink_message(mav, sock, msg)
    print("[NORMAL]   HEARTBEAT #2 gonderildi. (duplicate test)")
    wait_for_response(sock)

    sock.close()


def send_multi_client():
    """2 farkli UDP socket = 2 farkli kaynak port"""
    mav = create_mav()

    # Client A
    sock_a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    msg_a = mav.heartbeat_encode(
        type=mavutil.mavlink.MAV_TYPE_QUADROTOR,
        autopilot=mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA,
        base_mode=0, custom_mode=0,
        system_status=mavutil.mavlink.MAV_STATE_ACTIVE
    )
    send_mavlink_message(mav, sock_a, msg_a)
    print("[MULTI-A]  Client A: HEARTBEAT gonderildi.")
    wait_for_response(sock_a)

    time.sleep(0.1)

    # Client B (yeni socket = farkli kaynak port)
    sock_b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    msg_b = mav.param_set_encode(
        target_system=1, target_component=1,
        param_id=b"TEST_MODE\x00\x00\x00\x00\x00\x00\x00",
        param_value=1.0,
        param_type=mavutil.mavlink.MAV_PARAM_TYPE_REAL32
    )
    send_mavlink_message(mav, sock_b, msg_b)
    print("[MULTI-B]  Client B: PARAM_SET gonderildi.")
    wait_for_response(sock_b)

    sock_a.close()
    sock_b.close()


def send_heartbeat_burst(count=12):
    """
    Kisa surede burst threshold'u asan sayida (orn: 12) HEARTBEAT gonderir (Asama 8).
    Beklenen: Ilk 10 mesaj NORMAL, ardindan esik asilinca SUSPIC.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    mav = create_mav()
    msg = mav.heartbeat_encode(
        type=mavutil.mavlink.MAV_TYPE_QUADROTOR,
        autopilot=mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA,
        base_mode=0, custom_mode=0,
        system_status=mavutil.mavlink.MAV_STATE_ACTIVE
    )

    print(f"[BURST]    Hizli sekilde {count} adet HEARTBEAT gonderiliyor...")
    for i in range(count):
        send_mavlink_message(mav, sock, msg)
        time.sleep(0.02)  # Cok kisa araliklarla gonder

    wait_for_response(sock)
    sock.close()


def send_repeated_param_set(count=4):
    """
    Kisa surede repeated PARAM_SET gonderir (Asama 8).
    Beklenen: SUSPIC
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    mav = create_mav()
    msg = mav.param_set_encode(
        target_system=1, target_component=1,
        param_id=b"BURST_PARAM\x00\x00\x00\x00\x00",
        param_value=99.0,
        param_type=mavutil.mavlink.MAV_PARAM_TYPE_REAL32
    )

    print(f"[REPEATED] Hizli sekilde {count} adet PARAM_SET gonderiliyor...")
    for i in range(count):
        send_mavlink_message(mav, sock, msg)
        time.sleep(0.05)

    wait_for_response(sock)
    sock.close()


# ================================================
# ANA TEST AKISI
# ================================================

def main():
    print("=" * 55)
    print("  MAVLink Honeypot - Kapsamli Test (Asama 5)")
    print("=" * 55)

    # --- TEST 1-7: Tum MAVLink mesaj tipleri ---
    print("\n--- 7 MAVLink Mesaj Testi ---")

    send_heartbeat()
    time.sleep(0.1)

    send_attitude()
    time.sleep(0.1)

    send_sys_status()
    time.sleep(0.1)

    send_global_position_int()
    time.sleep(0.1)

    send_param_request_list()
    time.sleep(0.1)

    send_param_set()
    time.sleep(0.1)

    send_command_long()
    time.sleep(0.1)

    # --- TEST 8: Gecersiz duz metin ---
    print("\n--- Gecersiz Veri Testi ---")

    send_hello()
    time.sleep(0.1)

    # --- TEST 9: Rastgele byte ---
    print("\n--- Bozuk Veri Testi ---")

    send_random_bytes()
    time.sleep(0.1)

    # --- TEST 10: Duplicate HEARTBEAT ---
    print("\n--- Duplicate Mesaj Testi ---")

    send_duplicate_heartbeat()
    time.sleep(0.1)

    # --- TEST 11: Multi-client ---
    print("\n--- Multi-Client Testi ---")

    send_multi_client()
    time.sleep(0.1)

    # --- TEST 12: Server Stability & Recovery Test ---
    print("\n--- Server Stability Testi (Invalid Veri Sonrasi Kurtarma) ---")
    print("  Invalid/bozuk veri sonrasi tekrar HEARTBEAT gonderiliyor...")
    send_heartbeat()
    time.sleep(0.1)
    print("  Invalid/bozuk veri sonrasi tekrar PARAM_SET gonderiliyor...")
    send_param_set()
    time.sleep(2.5)  # Onceki trafik sliding window'dan ciksin

    # --- TEST 13: Asama 8 Davranissal Analiz (Behavior Analyzer) Testi ---
    print("\n--- Asama 8 Davranissal Analiz Testi (Burst & Repeated Messages) ---")
    send_heartbeat_burst(count=12)
    time.sleep(0.5)
    send_repeated_param_set(count=4)

    # --- SONUC ---
    print()
    print("=" * 55)
    print("  Tum testler basariyla tamamlandi.")
    print("=" * 55)


if __name__ == "__main__":
    main()
