# test_classifier.py
# Asama 6: Event Classifier Otomatik Testleri

import sys
import os
import unittest

# Kok dizini python path'ine ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from event_classifier import classify_message


class TestEventClassifier(unittest.TestCase):
    """
    MAVLink mesaj tipine gore yapilan NORMAL / SUSPIC siniflandirma testleri
    """

    def test_normal_messages(self):
        """Standard ucus ve durum mesajlari NORMAL olarak siniflandirilmali"""
        normal_types = [
            "HEARTBEAT",
            "SYS_STATUS",
            "ATTITUDE",
            "GLOBAL_POSITION_INT"
        ]
        for msg_type in normal_types:
            with self.subTest(msg_type=msg_type):
                status = classify_message(msg_type)
                self.assertEqual(status, "NORMAL", f"{msg_type} icin status NORMAL olmaliydi")

    def test_suspicious_messages(self):
        """Kritik parametre ve komut mesajlari SUSPIC olarak siniflandirilmali"""
        suspicious_types = [
            "PARAM_REQUEST_LIST",
            "PARAM_SET",
            "COMMAND_LONG"
        ]
        for msg_type in suspicious_types:
            with self.subTest(msg_type=msg_type):
                status = classify_message(msg_type)
                self.assertEqual(status, "SUSPIC", f"{msg_type} icin status SUSPIC olmaliydi")

    def test_unknown_and_custom_messages(self):
        """Bilinmeyen veya tanimlanmamis mesajlar NORMAL kabul edilmeli"""
        unknown_types = [
            "UNKNOWN",
            "HELLO MAVLINK",
            "PING",
            "MISSION_COUNT",
            "BAD_DATA",
            "RANDOM_PACKET"
        ]
        for msg_type in unknown_types:
            with self.subTest(msg_type=msg_type):
                status = classify_message(msg_type)
                self.assertEqual(status, "NORMAL", f"{msg_type} icin status NORMAL olmaliydi")


if __name__ == "__main__":
    unittest.main()
