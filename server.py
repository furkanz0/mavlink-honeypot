# server.py
# MAVLink Honeypot - UDP Server
# Asama 1: UDP uzerinden mesaj alir
# Asama 2: Gercek MAVLink mesajlarini parse eder
# Asama 3: Mesaj tipine gore NORMAL/SUSPIC siniflandirmasi yapar
# Asama 4: Sahte MAVLink cevaplari gonderir (honeypot tuzagi)
# Her olayi events.json dosyasina kaydeder

import socket
import sys
from datetime import datetime
from mavlink_handler import parse_mavlink, get_message_info
from event_classifier import classify_message
from behavior_analyzer import analyze_behavior
from event_logger import log_event, ensure_events_file
from mavlink_responder import create_responder, generate_response

HOST = "0.0.0.0"
PORT = 14550

def main():
    # events.json dosyasinin varligini garanti et (Asama 6)
    ensure_events_file()

    # UDP server olustur
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, PORT))

    # Sahte cevap gondermek icin MAVLink nesnesi olustur
    responder = create_responder()

    print("MAVLink Honeypot UDP Server baslatildi...")
    print(f"Dinleniyor: {HOST}:{PORT}")
    print("Sahte cevap sistemi aktif.\n")
    sys.stdout.flush()

    try:
        while True:
            try:
                # UDP verisini al (kaynak IP ve port dahil)
                data, addr = sock.recvfrom(1024)
            except ConnectionResetError:
                # Windows'ta istemci portu kapandiginda olusan ICMP port unreachable hatasini yut
                continue

            source_ip = addr[0]
            source_port = addr[1]
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            try:
                # Gelen veriyi MAVLink olarak parse et
                msg = parse_mavlink(data)

                if msg is not None and msg.get_type() != "BAD_DATA":
                    # MAVLink mesaji basariyla parse edildi
                    info = get_message_info(msg)
                    message_type = info["type"]

                    # Mesaj tipine gore status belirle (Asama 3)
                    status = classify_message(message_type)

                    # Davranissal analiz ile status guncelle (Asama 8)
                    status = analyze_behavior(source_ip, source_port, message_type, status)

                    # Terminal ciktisi
                    print("--------------------------------")
                    print(f"  {message_type} alindi")
                    print(f"  Time: {timestamp}")
                    print(f"  IP: {source_ip}")
                    print(f"  Port: {source_port}")
                    print(f"  Protocol: UDP")
                    print(f"  Status: {status}")
                    print(f"  System ID: {info['system_id']}")
                    print(f"  Component ID: {info['component_id']}")

                    # Sahte cevap gonder (Asama 4)
                    response_bytes, description = generate_response(responder, message_type)
                    if response_bytes:
                        sock.sendto(response_bytes, addr)
                        print(f"  >> {description}")
                    elif description:
                        print(f"  >> {description}")

                    print("--------------------------------")
                    print()

                else:
                    # MAVLink olmayan veya gecersiz veri
                    message_type = "UNKNOWN"
                    status = "NORMAL"

                    # Davranissal analiz (Asama 8)
                    status = analyze_behavior(source_ip, source_port, message_type, status)

                    # Terminal ciktisi
                    print("--------------------------------")
                    print("  Gecersiz veya taninmayan MAVLink verisi")
                    print(f"  Time: {timestamp}")
                    print(f"  IP: {source_ip}")
                    print(f"  Port: {source_port}")
                    print(f"  Protocol: UDP")
                    print(f"  Status: {status}")
                    print(f"  Ham veri: {data}")
                    print("--------------------------------")
                    print()

                # Olayi events.json dosyasina kaydet
                log_event(
                    timestamp=timestamp,
                    source_ip=source_ip,
                    source_port=source_port,
                    protocol="UDP",
                    message_type=message_type,
                    status=status
                )

            except Exception as e:
                # Tek bir mesaj hatasi server'i durdurmasin (Asama 5)
                print("--------------------------------")
                print(f"  [HATA] Mesaj islenirken hata: {e}")
                print(f"  IP: {source_ip}")
                print(f"  Port: {source_port}")
                print("  Server calismaya devam ediyor.")
                print("--------------------------------")
                print()

            sys.stdout.flush()

    except KeyboardInterrupt:
        print("\nServer kapatildi.")
    finally:
        sock.close()

if __name__ == "__main__":
    main()

