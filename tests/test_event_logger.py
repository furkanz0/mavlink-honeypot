# test_event_logger.py
# Asama 6: Event Logger Otomatik Testleri

import sys
import os
import json
import tempfile
import unittest

# Kok dizini python path'ine ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from event_logger import log_event, _read_events, _write_events


class TestEventLogger(unittest.TestCase):
    """
    event_logger.py ve JSON dosya yonetimi testleri
    """

    def setUp(self):
        # Her test icin izole gecici bir json dosyasi olustur
        self.temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        self.temp_file_path = self.temp_file.name
        self.temp_file.close()

    def tearDown(self):
        # Gecici test dosyasini temizle
        if os.path.exists(self.temp_file_path):
            os.remove(self.temp_file_path)

    # Test 1 - Bos JSON array'e event ekle
    def test_log_event_to_empty_array(self):
        """Bos bir JSON array'e ([]) 1 event ekleme testi"""
        with open(self.temp_file_path, "w", encoding="utf-8") as f:
            f.write("[]")

        success = log_event(
            timestamp="2026-10-02 14:32:15",
            source_ip="127.0.0.1",
            source_port=54321,
            protocol="UDP",
            message_type="HEARTBEAT",
            status="NORMAL",
            file_path=self.temp_file_path
        )
        self.assertTrue(success)

        events = _read_events(self.temp_file_path)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["message_type"], "HEARTBEAT")
        self.assertEqual(events[0]["status"], "NORMAL")
        self.assertEqual(events[0]["source_port"], 54321)

    # Test 2 - Mevcut 1 event'in uzerine yeni event ekle
    def test_log_event_append_existing(self):
        """Mevcut 1 event bulunan dosyaya yeni event ekleme testi (Toplam 2 event olmali)"""
        initial_event = {
            "timestamp": "2026-10-02 14:32:15",
            "source_ip": "127.0.0.1",
            "source_port": 54321,
            "protocol": "UDP",
            "message_type": "HEARTBEAT",
            "status": "NORMAL"
        }
        with open(self.temp_file_path, "w", encoding="utf-8") as f:
            json.dump([initial_event], f)

        success = log_event(
            timestamp="2026-10-02 14:32:16",
            source_ip="127.0.0.1",
            source_port=54322,
            protocol="UDP",
            message_type="ATTITUDE",
            status="NORMAL",
            file_path=self.temp_file_path
        )
        self.assertTrue(success)

        events = _read_events(self.temp_file_path)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["message_type"], "HEARTBEAT")
        self.assertEqual(events[1]["message_type"], "ATTITUDE")

    # Test 3 - Ayni event'i iki kez ekle (Deduplication YOK)
    def test_log_duplicate_events(self):
        """Ayni event arka arkaya 2 kez eklendiginde ikisi de kaydedilmeli (Deduplication engellenmez)"""
        with open(self.temp_file_path, "w", encoding="utf-8") as f:
            f.write("[]")

        # 1. ekleme
        log_event(
            timestamp="2026-10-02 14:32:15",
            source_ip="127.0.0.1",
            source_port=54321,
            protocol="UDP",
            message_type="HEARTBEAT",
            status="NORMAL",
            file_path=self.temp_file_path
        )

        # 2. ekleme (tamamen ayni veriler)
        log_event(
            timestamp="2026-10-02 14:32:15",
            source_ip="127.0.0.1",
            source_port=54321,
            protocol="UDP",
            message_type="HEARTBEAT",
            status="NORMAL",
            file_path=self.temp_file_path
        )

        events = _read_events(self.temp_file_path)
        self.assertEqual(len(events), 2, "Duplicate engellenmemeli, iki event kaydedilmeli")

    # Test 4 - Gecersiz event eklemeyi dene
    def test_reject_invalid_event(self):
        """Gecersiz event (orn: yanlis status veya port tipi) events.json'a yazilmamali"""
        initial_event = {
            "timestamp": "2026-10-02 14:32:15",
            "source_ip": "127.0.0.1",
            "source_port": 54321,
            "protocol": "UDP",
            "message_type": "HEARTBEAT",
            "status": "NORMAL"
        }
        with open(self.temp_file_path, "w", encoding="utf-8") as f:
            json.dump([initial_event], f)

        # Gecersiz status: SUSPICIOUS
        success1 = log_event(
            timestamp="2026-10-02 14:32:17",
            source_ip="127.0.0.1",
            source_port=54323,
            protocol="UDP",
            message_type="COMMAND_LONG",
            status="SUSPICIOUS",  # Yasak! Sadece SUSPIC olmali
            file_path=self.temp_file_path
        )
        self.assertFalse(success1)

        # Gecersiz protocol: HTTP
        success2 = log_event(
            timestamp="2026-10-02 14:32:18",
            source_ip="127.0.0.1",
            source_port=54324,
            protocol="HTTP",      # Yasak! Sadece UDP/TCP
            message_type="HEARTBEAT",
            status="NORMAL",
            file_path=self.temp_file_path
        )
        self.assertFalse(success2)

        # Dosyadaki event sayisi degismemeli (hala 1 olmali)
        events = _read_events(self.temp_file_path)
        self.assertEqual(len(events), 1)

    # Durum 1 - Dosya hic yoksa otomatik olusturma
    def test_file_does_not_exist(self):
        """Dosya yokken okuma ve yazma guvenle calismali"""
        os.remove(self.temp_file_path)
        self.assertFalse(os.path.exists(self.temp_file_path))

        events = _read_events(self.temp_file_path)
        self.assertEqual(events, [])
        self.assertTrue(os.path.exists(self.temp_file_path))

    # Durum 2 - Dosya bossa
    def test_file_is_empty(self):
        """0 byte'lik bos dosyayi okuma guvenle [] dondurmeli"""
        with open(self.temp_file_path, "w", encoding="utf-8") as f:
            f.write("")

        events = _read_events(self.temp_file_path)
        self.assertEqual(events, [])

    # Durum 4 - Bozuk JSON dosyasi
    def test_corrupted_json_file(self):
        """Bozuk JSON iceren dosya server'i cokertmemeli ve silinmemeli"""
        corrupted_content = "{ this is bad json: [1, 2, "
        with open(self.temp_file_path, "w", encoding="utf-8") as f:
            f.write(corrupted_content)

        # Okuma yapildiginda exception firlatmamali, guvenli liste donmeli
        events = _read_events(self.temp_file_path)
        self.assertEqual(events, [])

        # Dosyanin hala var oldugunu ve silinmedigini kontrol et
        self.assertTrue(os.path.exists(self.temp_file_path))
        with open(self.temp_file_path, "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), corrupted_content)


if __name__ == "__main__":
    unittest.main()
