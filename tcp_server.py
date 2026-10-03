# tcp_server.py
# MAVLink Honeypot - TCP Server
# Asama 9: TCP Desteği ve Coklu Istemci Yonetimi

import socket
import sys
import threading
from datetime import datetime
from mavlink_handler import parse_mavlink_data, get_message_info
from event_classifier import classify_message
from behavior_analyzer import analyze_behavior
from event_logger import log_event, ensure_events_file
from mavlink_responder import create_responder, generate_response

TCP_HOST = "0.0.0.0"
TCP_PORT = 14551


def handle_tcp_client(client_sock, client_addr):
    """
    Her bir TCP istemci baglantisini ayri bir thread icerisinde yonetir.
    """
    source_ip = client_addr[0]
    source_port = client_addr[1]

    # Her baglanti veya thread icin responder nesnesi
    responder = create_responder()

    print(f"[TCP] Yeni baglanti kabul edildi: {source_ip}:{source_port}")
    sys.stdout.flush()

    try:
        while True:
            # TCP verisini al
            data = client_sock.recv(1024)
            if not data:
                # Istemci baglantiyi kapatti
                break

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            try:
                # Gelen veriyi MAVLink olarak parse et (ortak parse_mavlink_data)
                msg = parse_mavlink_data(data)

                if msg is not None and msg.get_type() != "BAD_DATA":
                    info = get_message_info(msg)
                    message_type = info["type"]

                    # 1. Kural tabanli siniflandirici
                    status = classify_message(message_type)

                    # 2. Davranissal analiz (Asama 8)
                    status = analyze_behavior(source_ip, source_port, message_type, status)

                    # Terminal ciktisi
                    print("--------------------------------")
                    print(f"  [TCP] {message_type} alindi")
                    print(f"  Time: {timestamp}")
                    print(f"  IP: {source_ip}")
                    print(f"  Port: {source_port}")
                    print(f"  Protocol: TCP")
                    print(f"  Status: {status}")
                    print(f"  System ID: {info['system_id']}")
                    print(f"  Component ID: {info['component_id']}")

                    # Sahte cevap gonder (Asama 4 & 9)
                    response_bytes, description = generate_response(responder, message_type)
                    if response_bytes:
                        client_sock.sendall(response_bytes)
                        print(f"  >> {description}")
                    elif description:
                        print(f"  >> {description}")

                    print("--------------------------------")
                    print()

                else:
                    # MAVLink olmayan veya gecersiz veri
                    message_type = "UNKNOWN"
                    status = "NORMAL"

                    # Davranissal analiz
                    status = analyze_behavior(source_ip, source_port, message_type, status)

                    # Terminal ciktisi
                    print("--------------------------------")
                    print("  [TCP] Gecersiz veya taninmayan MAVLink verisi")
                    print(f"  Time: {timestamp}")
                    print(f"  IP: {source_ip}")
                    print(f"  Port: {source_port}")
                    print(f"  Protocol: TCP")
                    print(f"  Status: {status}")
                    print(f"  Ham veri: {data}")
                    print("--------------------------------")
                    print()

                # Olayi events.json dosyasina kaydet (protocol = "TCP")
                log_event(
                    timestamp=timestamp,
                    source_ip=source_ip,
                    source_port=source_port,
                    protocol="TCP",
                    message_type=message_type,
                    status=status
                )

            except Exception as e:
                # Tek bir paket hatasi TCP baglantisini veya server'i dusurmesin
                print(f"[TCP HATA] Paket isleme hatasi ({source_ip}:{source_port}): {e}", file=sys.stderr)

            sys.stdout.flush()

    except Exception as e:
        print(f"[TCP HATA] Istemci soket hatasi ({source_ip}:{source_port}): {e}", file=sys.stderr)
    finally:
        try:
            client_sock.close()
        except Exception:
            pass
        print(f"[TCP] Baglanti kapatildi: {source_ip}:{source_port}")
        sys.stdout.flush()


def run_tcp_server(host=TCP_HOST, port=TCP_PORT, stop_event=None):
    """
    TCP Server'i baslatir ve gelen baglantilari thread'lere dagitir.
    """
    ensure_events_file()

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # stop_event kontrolu icin kisa bir timeout
    server_sock.settimeout(1.0)
    server_sock.bind((host, port))
    server_sock.listen(5)

    print("MAVLink Honeypot TCP Server baslatildi...")
    print(f"Dinleniyor: {host}:{port}")
    print("TCP Coklu Istemci ve Sahte cevap sistemi aktif.\n")
    sys.stdout.flush()

    try:
        while True:
            if stop_event and stop_event.is_set():
                break
            try:
                client_sock, client_addr = server_sock.accept()
            except socket.timeout:
                continue

            # Her istemci icin ayri thread
            t = threading.Thread(
                target=handle_tcp_client,
                args=(client_sock, client_addr),
                daemon=True
            )
            t.start()

    except KeyboardInterrupt:
        print("\nTCP Server kapatiliyor...")
    finally:
        server_sock.close()


if __name__ == "__main__":
    run_tcp_server()
