# event_logger.py
# events.json dosyasina olay kaydeden modul
# Honeypot ile Dashboard arasindaki ortak veri kaynagina yazar
# Asama 6: Event Validator entegrasyonu ve Gelismis JSON Dosyasi Korumasi

import json
import os
import sys
import threading
from event_validator import validate_event_with_reason

# events.json dosyasinin varsayilan yolu (server.py ile ayni klasorde)
EVENTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "events.json")

# Eszamanli (UDP ve TCP thread'leri) yazmalarda dosya bozulmasini onleyen kilit (Lock)
_file_lock = threading.Lock()


def ensure_events_file(file_path=None):
    """
    events.json dosyasinin varligini garanti eder.
    Dosya yoksa [] ile baslatir.
    """
    target_file = file_path or EVENTS_FILE
    if not os.path.exists(target_file):
        try:
            with open(target_file, "w", encoding="utf-8") as f:
                f.write("[]")
        except IOError as e:
            print(f"[HATA] events.json olusturulamadi: {e}", file=sys.stderr)


def log_event(timestamp, source_ip, source_port, protocol, message_type, status, file_path=None):
    """
    events.json dosyasina yeni bir olay ekler.
    Mevcut olaylari silmez, listenin sonuna ekler (Deduplication yapilmaz).
    Event, event_validator uzerinden kontrol edilir.
    Gecersiz ise dosyaya YAZILMAZ ve terminale hata mesaji basilir.
    """
    target_file = file_path or EVENTS_FILE

    # Olay verisini olustur (ortak sozlesme formatinda)
    event = {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "source_port": source_port,
        "protocol": protocol,
        "message_type": message_type,
        "status": status
    }

    # Event format validation (Asama 6 - event_validator entegrasyonu)
    is_valid, reason = validate_event_with_reason(event)
    if not is_valid:
        print(f"[VALIDATION HATA] Event gecersiz, events.json dosyasina yazilmadi!", file=sys.stderr)
        print(f"  Neden: {reason}", file=sys.stderr)
        print(f"  Event: {event}", file=sys.stderr)
        return False

    # Mevcut olaylari oku ve yeni olayi ekle (Thread-safe)
    with _file_lock:
        events = _read_events(target_file)
        events.append(event)
        _write_events(events, target_file)

    return True


def _read_events(file_path=None):
    """
    events.json dosyasini guvenli sekilde okur.
    Durum 1: Dosya yoksa olusturur ve [] dondurur.
    Durum 2: Dosya bossa [] olarak kabul eder.
    Durum 3: Dosyada gecerli JSON array varsa listeyi dondurur.
    Durum 4: Dosyada bozuk JSON varsa server cokmez, hata bildirir ve mevcut dosyayi silmeden guvenle devam eder.
    """
    target_file = file_path or EVENTS_FILE

    # Durum 1: Dosya yoksa otomatik olustur
    if not os.path.exists(target_file):
        try:
            with open(target_file, "w", encoding="utf-8") as f:
                f.write("[]")
            return []
        except IOError as e:
            print(f"[HATA] Dosya olusturulamadi ({target_file}): {e}", file=sys.stderr)
            return []

    # Durum 2 & 3 & 4: Dosyayi oku
    try:
        with open(target_file, "r", encoding="utf-8") as f:
            content = f.read().strip()
            # Durum 2: Dosya bossa [] kabul et
            if not content:
                return []
            data = json.loads(content)
            # Durum 3: Gecerli JSON array
            if isinstance(data, list):
                return data
            else:
                print(f"[HATA] {target_file} bir JSON listesi degil! Guvenli modda bos liste ile devam ediliyor.", file=sys.stderr)
                return []
    except json.JSONDecodeError as e:
        # Durum 4: Bozuk JSON varsa server cokmemeli, anlasilir hata gosterilmeli, dosya sessizce silinmemeli
        print(f"[HATA] {target_file} bozuk veya gecersiz JSON formatinda ({e})!", file=sys.stderr)
        print("  Mevcut dosya silinmedi ve korunuyor. Guvenli modda bos event listesi ile devam ediliyor.", file=sys.stderr)
        return []
    except IOError as e:
        print(f"[HATA] Dosya okuma hatasi ({target_file}): {e}", file=sys.stderr)
        return []


def _write_events(events, file_path=None):
    """
    Olay listesini events.json dosyasina yazar.
    JSON her zaman gecerli formatta kalir.
    """
    target_file = file_path or EVENTS_FILE
    try:
        with open(target_file, "w", encoding="utf-8") as f:
            json.dump(events, f, indent=4, ensure_ascii=False)
    except IOError as e:
        print(f"[HATA] events.json dosyasina yazilamadi ({target_file}): {e}", file=sys.stderr)
