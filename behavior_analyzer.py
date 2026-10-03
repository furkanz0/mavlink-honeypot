# behavior_analyzer.py
# MAVLink Honeypot - Davranissal Analiz Modulu
# Asama 8: Gelismis Suspicious Davranis Tespiti
#
# Mesaj tipine ek olarak istemcinin (source_ip veya source_ip:port)
# kisa sure icerisindeki mesaj trafigini ve desenlerini analiz eder.

import time
from collections import defaultdict, deque

# ==============================================================
# ESİK VE ZAMAN PENCERESİ TANIMLARI (Thresholds)
# ==============================================================
# 1. Genel Mesaj Burst Eşiği:
#    Aynı kaynaktan BURST_WINDOW_SECONDS içerisinde gelen toplam mesaj
#    sayısı BURST_THRESHOLD değerini aşarsa trafik SUSPIC kabul edilir.
#    (Örn: 5 normal HEARTBEAT false positive üretmez; fakat 2 saniyede
#     10'dan fazla mesaj DoS veya agresif tarama davranışı sayılır)
BURST_WINDOW_SECONDS = 2.0
BURST_THRESHOLD = 10

# 2. Tekrarlanan PARAM_SET Eşiği:
#    Zaman penceresi içinde PARAM_SET_THRESHOLD üzerinde parametre
#    değiştirme denemesi tespit edilirse SUSPIC olarak işaretlenir.
PARAM_SET_WINDOW_SECONDS = 5.0
PARAM_SET_THRESHOLD = 3

# 3. Tekrarlanan COMMAND_LONG Eşiği:
#    Zaman penceresi içinde COMMAND_LONG_THRESHOLD üzerinde kritik komut
#    gönderimi tespit edilirse SUSPIC olarak işaretlenir.
COMMAND_LONG_WINDOW_SECONDS = 5.0
COMMAND_LONG_THRESHOLD = 3

# 4. Bellek Temizliği (Memory Management) Penceresi:
#    Bu süreden daha eski tüm mesaj kayıtları bellekten (RAM) silinir.
MAX_HISTORY_SECONDS = 10.0


class BehaviorAnalyzer:
    """
    Kaynak IP (veya IP:port) bazli zaman kaydirmali (sliding window)
    MAVLink trafik analizi yapar.
    """

    def __init__(self, use_port=False):
        """
        Args:
            use_port (bool): True ise (source_ip, source_port) bazinda takip yapar,
                             False ise sadece source_ip bazinda takip yapar.
        """
        self.use_port = use_port
        # Her kaynak icin (timestamp, message_type) ciftlerini saklayan deque
        self.history = defaultdict(deque)

    def _get_key(self, source_ip, source_port):
        """Kaynagi temsil eden anahtari dondurur"""
        if self.use_port:
            return f"{source_ip}:{source_port}"
        return str(source_ip)

    def _cleanup_old_records(self, key, current_time):
        """
        MAX_HISTORY_SECONDS suresinden eski kayitlari temizler (Memory Management).
        """
        records = self.history[key]
        cutoff_time = current_time - MAX_HISTORY_SECONDS
        while records and records[0][0] < cutoff_time:
            records.popleft()

        # Eger kayit kalmadiysa anahtari tamamen sozlukten sil
        if not records:
            del self.history[key]

    def analyze_message(self, source_ip, source_port, message_type, current_status, current_time=None):
        """
        Gelen mesaji davranissal kurallara gore degerlendirir.

        Kurallar:
        1. Eger classifier zaten "SUSPIC" dediyse asla "NORMAL"e dusurulmez.
        2. Kaynak gecmisi kaydedilir ve eski kayitlar temizlenir.
        3. Burst kontrolu: Kisa surede asiri mesaj gelirse -> "SUSPIC"
        4. Tekrarlanan PARAM_SET kontrolu -> "SUSPIC"
        5. Tekrarlanan COMMAND_LONG kontrolu -> "SUSPIC"

        Args:
            source_ip (str): Kaynak IP adresi
            source_port (int): Kaynak port
            message_type (str): MAVLink mesaj tipi (HEARTBEAT, PARAM_SET vb.)
            current_status (str): Classifier'dan gelen mevcut durum ("NORMAL" veya "SUSPIC")
            current_time (float, optional): Testler icin opsiyonel zaman damgasi (varsayilan: time.time())

        Returns:
            str: "NORMAL" veya "SUSPIC"
        """
        if current_time is None:
            current_time = time.time()

        key = self._get_key(source_ip, source_port)

        # Yeni mesaji gecmise ekle
        self.history[key].append((current_time, message_type))

        # Eski kayitlari temizle (Memory Management)
        self._cleanup_old_records(key, current_time)

        # Kural: Classifier zaten SUSPIC dediyse status ASLA NORMAL'e dusurulemez!
        final_status = current_status

        records = self.history.get(key, [])

        # --- A. MESSAGE BURST KONTROLU ---
        # Son BURST_WINDOW_SECONDS icindeki toplam mesaj sayisi
        burst_cutoff = current_time - BURST_WINDOW_SECONDS
        recent_total_messages = sum(1 for t, _ in records if t >= burst_cutoff)

        if recent_total_messages > BURST_THRESHOLD:
            final_status = "SUSPIC"

        # --- B. REPEATED PARAM_SET KONTROLU ---
        param_set_cutoff = current_time - PARAM_SET_WINDOW_SECONDS
        recent_param_sets = sum(1 for t, m in records if t >= param_set_cutoff and m == "PARAM_SET")

        if recent_param_sets >= PARAM_SET_THRESHOLD:
            final_status = "SUSPIC"

        # --- C. REPEATED COMMAND_LONG KONTROLU ---
        cmd_long_cutoff = current_time - COMMAND_LONG_WINDOW_SECONDS
        recent_cmd_longs = sum(1 for t, m in records if t >= cmd_long_cutoff and m == "COMMAND_LONG")

        if recent_cmd_longs >= COMMAND_LONG_THRESHOLD:
            final_status = "SUSPIC"

        return final_status

    def clear(self):
        """Hafizayi sifirlar (Testler icin kolaylik)"""
        self.history.clear()


# Tekil / Global analyzer ornegi
_default_analyzer = BehaviorAnalyzer(use_port=True)


def analyze_behavior(source_ip, source_port, message_type, current_status, current_time=None):
    """
    Global BehaviorAnalyzer ornegi uzerinden mesaj analiz eder.
    """
    return _default_analyzer.analyze_message(
        source_ip=source_ip,
        source_port=source_port,
        message_type=message_type,
        current_status=current_status,
        current_time=current_time
    )


def clear_history():
    """Global analyzer gecmisini sifirlar (Test izolasyonu icin)"""
    _default_analyzer.clear()
