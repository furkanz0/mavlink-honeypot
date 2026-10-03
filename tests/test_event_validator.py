# test_event_validator.py
# Asama 6: Event Validator Otomatik Testleri

import sys
import os
import unittest

# Kok dizini python path'ine ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from event_validator import validate_event, validate_event_with_reason


class TestEventValidator(unittest.TestCase):
    """
    events.json sozlesmesini dogrulayan unit testler
    """

    def setUp(self):
        # Referans gecerli event
        self.valid_event = {
            "timestamp": "2026-10-02 14:32:15",
            "source_ip": "127.0.0.1",
            "source_port": 54321,
            "protocol": "UDP",
            "message_type": "HEARTBEAT",
            "status": "NORMAL"
        }

    # Test 1 - Gecerli event
    def test_valid_event(self):
        """Gecerli event dogrulanmali (PASS)"""
        is_valid, reason = validate_event_with_reason(self.valid_event)
        self.assertTrue(is_valid, f"Gecerli event reddedildi: {reason}")
        self.assertTrue(validate_event(self.valid_event))

    # Test 1.1 - Gecerli TCP ve SUSPIC durumu
    def test_valid_event_tcp_suspic(self):
        """Gecerli TCP protokolu ve SUSPIC statusu kabul edilmeli"""
        event = self.valid_event.copy()
        event["protocol"] = "TCP"
        event["status"] = "SUSPIC"
        event["message_type"] = "PARAM_SET"
        self.assertTrue(validate_event(event))

    # Test 2 - Eksik alan
    def test_missing_field_status(self):
        """status alani eksik oldugunda FAIL olmali"""
        event = self.valid_event.copy()
        del event["status"]
        self.assertFalse(validate_event(event))

    def test_missing_field_timestamp(self):
        """timestamp alani eksik oldugunda FAIL olmali"""
        event = self.valid_event.copy()
        del event["timestamp"]
        self.assertFalse(validate_event(event))

    # Test 3 - Fazladan alan
    def test_extra_field(self):
        """system_id gibi sozlesme disi alan eklendiginde FAIL olmali"""
        event = self.valid_event.copy()
        event["system_id"] = 1
        self.assertFalse(validate_event(event))

    def test_extra_field_attack_type(self):
        """is_attack, attack_type gibi alanlar eklendiginde FAIL olmali"""
        event = self.valid_event.copy()
        event["attack_type"] = "PARAMETER_INJECTION"
        self.assertFalse(validate_event(event))

    # Test 4 - Yanlis protocol
    def test_invalid_protocol(self):
        """'HTTP' gibi UDP/TCP harici protokollerde FAIL olmali"""
        event = self.valid_event.copy()
        event["protocol"] = "HTTP"
        self.assertFalse(validate_event(event))

    # Test 5 - Yanlis status
    def test_invalid_status_suspicious(self):
        """'SUSPICIOUS' kullanildiginda FAIL olmali (Sadece SUSPIC kabul edilir)"""
        event = self.valid_event.copy()
        event["status"] = "SUSPICIOUS"
        self.assertFalse(validate_event(event))

    def test_invalid_status_unknown(self):
        """Bilinmeyen status degerinde FAIL olmali"""
        event = self.valid_event.copy()
        event["status"] = "MALICIOUS"
        self.assertFalse(validate_event(event))

    # Test 6 - source_port yanlis tip
    def test_invalid_port_type_string(self):
        """source_port string oldugunda FAIL olmali"""
        event = self.valid_event.copy()
        event["source_port"] = "54321"
        self.assertFalse(validate_event(event))

    def test_invalid_port_type_boolean(self):
        """source_port boolean oldugunda FAIL olmali (Python bool int'tir)"""
        event = self.valid_event.copy()
        event["source_port"] = True
        self.assertFalse(validate_event(event))

    # Ek Testler - Diger tip kontrolleri
    def test_non_dict_event(self):
        """Event bir liste veya baska bir tip ise FAIL olmali"""
        self.assertFalse(validate_event(["not", "a", "dict"]))
        self.assertFalse(validate_event("string_event"))
        self.assertFalse(validate_event(None))

    def test_invalid_types_timestamp(self):
        """timestamp int veya baska tip ise FAIL olmali"""
        event = self.valid_event.copy()
        event["timestamp"] = 123456789
        self.assertFalse(validate_event(event))

    def test_invalid_types_source_ip(self):
        """source_ip string degilse FAIL olmali"""
        event = self.valid_event.copy()
        event["source_ip"] = 127001
        self.assertFalse(validate_event(event))

    def test_invalid_types_message_type(self):
        """message_type string degilse FAIL olmali"""
        event = self.valid_event.copy()
        event["message_type"] = 100
        self.assertFalse(validate_event(event))


if __name__ == "__main__":
    unittest.main()
