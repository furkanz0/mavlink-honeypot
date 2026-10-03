# event_classifier.py
# MAVLink mesaj tipine gore status siniflandirmasi yapar
# Asama 3 - Prototip siniflandirma (gercek saldir tespit sistemi degil)
#
# Bu dosya basit bir kural tabanli siniflandirici icerir.
# Amac: Honeypot tarafindan izlenmesi gereken supheli olaylari isaretlemek.

# Normal kabul edilen mesaj tipleri
# Bunlar standart ucus/durum mesajlaridir
NORMAL_MESSAGES = {
    "HEARTBEAT",
    "SYS_STATUS",
    "ATTITUDE",
    "GLOBAL_POSITION_INT",
}

# Supheli kabul edilen mesaj tipleri
# Bunlar parametre degistirme ve komut gonderme mesajlaridir
SUSPIC_MESSAGES = {
    "PARAM_REQUEST_LIST",
    "PARAM_SET",
    "COMMAND_LONG",
}


def classify_message(message_type):
    """
    MAVLink mesaj tipine gore status belirler.

    Kurallar:
        - NORMAL_MESSAGES icerisindeki mesajlar -> "NORMAL"
        - SUSPIC_MESSAGES icerisindeki mesajlar -> "SUSPIC"
        - Tanimlanmamis mesajlar                -> "NORMAL"

    Args:
        message_type: MAVLink mesaj tipi (ornegin "HEARTBEAT", "PARAM_SET")

    Returns:
        "NORMAL" veya "SUSPIC"
    """
    if message_type in SUSPIC_MESSAGES:
        return "SUSPIC"

    # Normal veya tanimlanmamis mesajlar
    return "NORMAL"
