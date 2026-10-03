# mavlink_handler.py
# MAVLink mesajlarini parse eden modul
# Asama 2 - Gercek MAVLink parsing

from pymavlink import mavutil

def parse_mavlink(raw_bytes):
    """
    Ham UDP byte verisini alir, MAVLink mesaji olarak parse eder.
    Basarili olursa parse edilen mesaji dondurur.
    Basarisiz olursa None dondurur.
    """
    try:
        # MAVLink parser olustur (MAVLink 2.0 destekli)
        mav = mavutil.mavlink.MAVLink(None)
        mav.robust_parsing = True

        # Ham byte verisini parse et
        messages = mav.parse_buffer(raw_bytes)

        # Parse edilen mesajlari kontrol et
        if messages and len(messages) > 0:
            return messages[0]
        else:
            return None

    except Exception as e:
        # Parse hatasi olursa None dondur
        return None


def parse_mavlink_data(raw_bytes):
    """
    UDP ve TCP sunuculari icin ortak MAVLink parse fonksiyonu.
    """
    return parse_mavlink(raw_bytes)


def get_message_info(msg):
    """
    Parse edilen MAVLink mesajindan bilgileri cikarir.
    Bir dictionary olarak dondurur.
    """
    info = {}

    # Mesaj tipini al
    info["type"] = msg.get_type()

    # System ID ve Component ID'yi al
    # MAVLink header'dan bu bilgilere erisiriz
    try:
        info["system_id"] = msg.get_srcSystem()
    except Exception:
        info["system_id"] = "Bilinmiyor"

    try:
        info["component_id"] = msg.get_srcComponent()
    except Exception:
        info["component_id"] = "Bilinmiyor"

    return info
