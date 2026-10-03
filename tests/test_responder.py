# test_responder.py
# Asama 10: MAVLink Responder Unit Testleri

import sys
import os
import unittest
from pymavlink import mavutil

# Kok dizini python path'ine ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from mavlink_responder import create_responder, generate_response


class TestMAVLinkResponder(unittest.TestCase):
    """
    Fake MAVLink cevap uretici modulunun testleri
    """

    def setUp(self):
        self.responder = create_responder()

    def _parse_response(self, response_bytes):
        mav = mavutil.mavlink.MAVLink(None)
        mav.robust_parsing = True
        msgs = mav.parse_buffer(response_bytes)
        self.assertTrue(len(msgs) > 0, "Cevap paketi parse edilemedi")
        return msgs[0]

    def test_heartbeat_response(self):
        """HEARTBEAT mesaji icin sahte HEARTBEAT uretilmeli"""
        resp_bytes, desc = generate_response(self.responder, "HEARTBEAT")
        self.assertIsNotNone(resp_bytes)
        self.assertIn("HEARTBEAT", desc)

        msg = self._parse_response(resp_bytes)
        self.assertEqual(msg.get_type(), "HEARTBEAT")

    def test_param_request_list_response(self):
        """PARAM_REQUEST_LIST mesaji icin sahte PARAM_VALUE uretilmeli"""
        resp_bytes, desc = generate_response(self.responder, "PARAM_REQUEST_LIST")
        self.assertIsNotNone(resp_bytes)
        self.assertIn("PARAM_VALUE", desc)

        msg = self._parse_response(resp_bytes)
        self.assertEqual(msg.get_type(), "PARAM_VALUE")

    def test_param_set_response(self):
        """PARAM_SET mesaji icin sahte PARAM_VALUE onay cevabi uretilmeli"""
        resp_bytes, desc = generate_response(self.responder, "PARAM_SET")
        self.assertIsNotNone(resp_bytes)
        self.assertIn("PARAM_VALUE", desc)

        msg = self._parse_response(resp_bytes)
        self.assertEqual(msg.get_type(), "PARAM_VALUE")

    def test_command_long_response(self):
        """COMMAND_LONG mesaji icin sahte COMMAND_ACK uretilmeli"""
        resp_bytes, desc = generate_response(self.responder, "COMMAND_LONG")
        self.assertIsNotNone(resp_bytes)
        self.assertIn("COMMAND_ACK", desc)

        msg = self._parse_response(resp_bytes)
        self.assertEqual(msg.get_type(), "COMMAND_ACK")

    def test_other_messages_no_response(self):
        """ATTITUDE, SYS_STATUS gibi mesajlar icin cevap uretilmemeli (None donmeli)"""
        for msg_type in ["ATTITUDE", "SYS_STATUS", "GLOBAL_POSITION_INT", "UNKNOWN"]:
            resp_bytes, desc = generate_response(self.responder, msg_type)
            self.assertIsNone(resp_bytes, f"{msg_type} icin sahte cevap gonderilmemeliydi")


if __name__ == "__main__":
    unittest.main()
