# tests/test_dashboard.py
# Dashboard ve log_reader testleri

import os
import json
import unittest
import tempfile
from pathlib import Path
from dashboard import log_reader
from dashboard.app import app


class TestDashboardLogReader(unittest.TestCase):
    def setUp(self):
        self.sample_events = [
            {
                "timestamp": "2026-10-03 12:00:00",
                "source_ip": "192.168.1.10",
                "source_port": 14550,
                "protocol": "UDP",
                "message_type": "HEARTBEAT",
                "status": "NORMAL"
            },
            {
                "timestamp": "2026-10-03 12:00:05",
                "source_ip": "192.168.1.20",
                "source_port": 54321,
                "protocol": "TCP",
                "message_type": "COMMAND_LONG",
                "status": "SUSPIC"
            },
            {
                "timestamp": "2026-10-03 12:00:10",
                "source_ip": "192.168.1.10",
                "source_port": 14550,
                "protocol": "UDP",
                "message_type": "PARAM_SET",
                "status": "SUSPIC"
            }
        ]

    def test_statistics_calculations(self):
        """İstatistik fonksiyonlarının doğru hesaplandığını doğrular"""
        events = self.sample_events
        self.assertEqual(log_reader.get_total_events(events), 3)
        self.assertEqual(log_reader.get_unique_ip_count(events), 2)
        self.assertEqual(log_reader.get_suspicious_count(events), 2)
        self.assertEqual(log_reader.get_last_event_time(events), "2026-10-03 12:00:10")

        msg_stats = log_reader.get_message_statistics(events)
        self.assertEqual(msg_stats["HEARTBEAT"], 1)
        self.assertEqual(msg_stats["COMMAND_LONG"], 1)
        self.assertEqual(msg_stats["PARAM_SET"], 1)

        status_stats = log_reader.get_status_statistics(events)
        self.assertEqual(status_stats["NORMAL"], 1)
        self.assertEqual(status_stats["SUSPIC"], 2)

    def test_empty_events(self):
        """Boş event listesi durumunu doğrular"""
        self.assertEqual(log_reader.get_total_events([]), 0)
        self.assertEqual(log_reader.get_unique_ip_count([]), 0)
        self.assertEqual(log_reader.get_suspicious_count([]), 0)
        self.assertIsNone(log_reader.get_last_event_time([]))
        self.assertEqual(log_reader.get_message_statistics([]), {})
        self.assertEqual(log_reader.get_status_statistics([]), {})

    def test_load_logs_from_custom_file(self):
        """Geçici dosya üzerinden okuma ve geçersiz alan filtreleme testi"""
        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json") as tmp:
            tmp_path = Path(tmp.name)
            data = [
                {
                    "timestamp": "2026-10-03 12:00:00",
                    "source_ip": "127.0.0.1",
                    "source_port": 14550,
                    "protocol": "UDP",
                    "message_type": "HEARTBEAT",
                    "status": "NORMAL"
                },
                {"invalid": "event_missing_fields"}
            ]
            json.dump(data, tmp)

        original_file = log_reader.LOG_FILE
        try:
            log_reader.LOG_FILE = tmp_path
            loaded = log_reader.load_logs()
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0]["message_type"], "HEARTBEAT")
        finally:
            log_reader.LOG_FILE = original_file
            if tmp_path.exists():
                os.unlink(tmp_path)


class TestDashboardFlaskRoute(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_dashboard_index(self):
        """Ana dashboard sayfasının 200 OK döndüğünü doğrular"""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"MAVLink Honeypot Security Dashboard", response.data)
        self.assertIn(b"Total Events", response.data)
        self.assertIn(b"Unique Source IPs", response.data)
        self.assertIn(b"Suspicious Events", response.data)


if __name__ == "__main__":
    unittest.main()
