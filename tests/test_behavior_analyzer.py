# test_behavior_analyzer.py
# Asama 8: Behavior Analyzer Otomatik Testleri

import sys
import os
import unittest

# Kok dizini python path'ine ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from behavior_analyzer import BehaviorAnalyzer, BURST_THRESHOLD, BURST_WINDOW_SECONDS


class TestBehaviorAnalyzer(unittest.TestCase):
    """
    behavior_analyzer modulu birim testleri
    """

    def setUp(self):
        # Her test icin temiz bir analyzer ornegi olustur (use_port=True: (ip, port) bazinda)
        self.analyzer = BehaviorAnalyzer(use_port=True)

    # Test 1: Normal HEARTBEAT
    def test_single_heartbeat_normal(self):
        """Tek bir HEARTBEAT mesaji NORMAL olarak degerlendirilmeli"""
        status = self.analyzer.analyze_message(
            source_ip="127.0.0.1",
            source_port=54321,
            message_type="HEARTBEAT",
            current_status="NORMAL",
            current_time=100.0
        )
        self.assertEqual(status, "NORMAL")

    # Test 2: PARAM_SET gonder
    def test_param_set_suspic(self):
        """PARAM_SET mesaji (classifier'dan SUSPIC gelirse) SUSPIC kalmali"""
        status = self.analyzer.analyze_message(
            source_ip="127.0.0.1",
            source_port=54321,
            message_type="PARAM_SET",
            current_status="SUSPIC",
            current_time=100.0
        )
        self.assertEqual(status, "SUSPIC")

    # Test 3: Kisa surede cok sayida HEARTBEAT (Message burst testi)
    def test_heartbeat_burst_becomes_suspicious(self):
        """
        BURST_THRESHOLD degerini asan hizli HEARTBEAT serisi
        davranissal olarak SUSPIC olarak isaretlenmeli.
        """
        base_time = 100.0
        # BURST_THRESHOLD kadar (orn: 10) mesaj gonder - hepsi NORMAL kalmali
        for i in range(BURST_THRESHOLD):
            status = self.analyzer.analyze_message(
                source_ip="127.0.0.1",
                source_port=54321,
                message_type="HEARTBEAT",
                current_status="NORMAL",
                current_time=base_time + (i * 0.1)  # 2 saniyelik pencere icinde
            )
            self.assertEqual(status, "NORMAL", f"Mesaj #{i+1} henuz esigi asmadi, NORMAL olmali")

        # 11. mesaj (BURST_THRESHOLD + 1) esigi asar -> SUSPIC olmali!
        burst_status = self.analyzer.analyze_message(
            source_ip="127.0.0.1",
            source_port=54321,
            message_type="HEARTBEAT",
            current_status="NORMAL",
            current_time=base_time + 1.1
        )
        self.assertEqual(burst_status, "SUSPIC", "Burst esigi asildiginda status SUSPIC olmali")

    # Test 4: Kisa surede cok sayida PARAM_SET
    def test_repeated_param_set(self):
        """Kisa surede tekrarlanan PARAM_SET mesajlari SUSPIC kalmali ve tespit edilmeli"""
        base_time = 200.0
        for i in range(5):
            status = self.analyzer.analyze_message(
                source_ip="127.0.0.1",
                source_port=54321,
                message_type="PARAM_SET",
                current_status="SUSPIC",
                current_time=base_time + (i * 0.2)
            )
            self.assertEqual(status, "SUSPIC")

    # Test 5: Iki farkli source IP birbirinden bagimsiz degerlendirilmeli
    def test_independent_source_ips(self):
        """
        Farkli source IP'ler birbirinin burst limitini etkilememeli.
        IP A burst yaparken, normal trafik ureten IP B NORMAL kalmali.
        """
        base_time = 300.0
        ip_a = "192.168.1.10"
        ip_b = "192.168.1.20"

        # IP A'ya esik asana kadar HEARTBEAT gonder (Burst tetikle)
        for i in range(BURST_THRESHOLD + 2):
            self.analyzer.analyze_message(
                source_ip=ip_a,
                source_port=50001,
                message_type="HEARTBEAT",
                current_status="NORMAL",
                current_time=base_time + (i * 0.05)
            )

        # IP A artik burst durumunda (SUSPIC)
        status_a = self.analyzer.analyze_message(
            source_ip=ip_a,
            source_port=50001,
            message_type="HEARTBEAT",
            current_status="NORMAL",
            current_time=base_time + 1.0
        )
        self.assertEqual(status_a, "SUSPIC")

        # IP B sadece 1 normal mesaj gonderiyor -> kesinlikle NORMAL olmali!
        status_b = self.analyzer.analyze_message(
            source_ip=ip_b,
            source_port=50002,
            message_type="HEARTBEAT",
            current_status="NORMAL",
            current_time=base_time + 1.0
        )
        self.assertEqual(status_b, "NORMAL", "IP B'nin trafigi IP A'nin burst'unden etkilenmemeli")

    # Test 5b: Ayni IP farkli portlar birbirinden bagimsiz olmali (use_port=True)
    def test_independent_source_ports(self):
        """
        Ayni IP adresinden gelen farkli portlar birbirinin burst limitini etkilememeli.
        Port 50001 burst yaparken, port 50002 NORMAL kalmali.
        """
        base_time = 350.0

        # Port 50001'e esik asana kadar HEARTBEAT gonder (Burst tetikle)
        for i in range(BURST_THRESHOLD + 2):
            self.analyzer.analyze_message(
                source_ip="127.0.0.1",
                source_port=50001,
                message_type="HEARTBEAT",
                current_status="NORMAL",
                current_time=base_time + (i * 0.05)
            )

        # Port 50001 artik burst durumunda (SUSPIC)
        status_a = self.analyzer.analyze_message(
            source_ip="127.0.0.1",
            source_port=50001,
            message_type="HEARTBEAT",
            current_status="NORMAL",
            current_time=base_time + 1.0
        )
        self.assertEqual(status_a, "SUSPIC")

        # Port 50002 sadece 1 normal mesaj gonderiyor -> kesinlikle NORMAL olmali!
        status_b = self.analyzer.analyze_message(
            source_ip="127.0.0.1",
            source_port=50002,
            message_type="HEARTBEAT",
            current_status="NORMAL",
            current_time=base_time + 1.0
        )
        self.assertEqual(status_b, "NORMAL", "Port 50002 trafigi port 50001'in burst'unden etkilenmemeli")

    # Test 6: False Positive kontrolu (Orn: 5 HEARTBEAT normal sayilmali)
    def test_false_positive_control_normal_heartbeats(self):
        """5 standart HEARTBEAT gonderildiginde false positive olusmamali (NORMAL kalmali)"""
        base_time = 400.0
        for i in range(5):
            status = self.analyzer.analyze_message(
                source_ip="127.0.0.1",
                source_port=54321,
                message_type="HEARTBEAT",
                current_status="NORMAL",
                current_time=base_time + (i * 0.2)
            )
            self.assertEqual(status, "NORMAL", "5 normal HEARTBEAT false positive uretmemeli")

    # Test 7: SUSPIC -> NORMAL dusurulemez kurali
    def test_no_downgrade_rule(self):
        """Classifier tarafindan SUSPIC isaretlenen bir event behavior tarafindan NORMAL'e dusurulemez"""
        status = self.analyzer.analyze_message(
            source_ip="127.0.0.1",
            source_port=54321,
            message_type="COMMAND_LONG",
            current_status="SUSPIC",
            current_time=500.0
        )
        self.assertEqual(status, "SUSPIC")

    # Test 8: Memory Management (Eski kayitlar silinmeli)
    def test_memory_cleanup_old_records(self):
        """MAX_HISTORY_SECONDS suresinden eski kayitlar RAM'den temizlenmeli"""
        t0 = 1000.0
        key = "127.0.0.1:54321"
        self.analyzer.analyze_message("127.0.0.1", 54321, "HEARTBEAT", "NORMAL", current_time=t0)
        self.assertEqual(len(self.analyzer.history[key]), 1)

        # 15 saniye sonra yeni mesaj gelince t0 kaydi silinmis olmali
        t1 = 1015.0
        self.analyzer.analyze_message("127.0.0.1", 54321, "HEARTBEAT", "NORMAL", current_time=t1)
        self.assertEqual(len(self.analyzer.history[key]), 1)
        self.assertEqual(self.analyzer.history[key][0][0], t1)

    # Test 9: Repeated COMMAND_LONG
    def test_repeated_command_long(self):
        """Kisa surede tekrarlanan COMMAND_LONG mesajlari SUSPIC olmali"""
        base_time = 600.0
        for i in range(5):
            status = self.analyzer.analyze_message(
                source_ip="127.0.0.1",
                source_port=54321,
                message_type="COMMAND_LONG",
                current_status="SUSPIC",
                current_time=base_time + (i * 0.2)
            )
            self.assertEqual(status, "SUSPIC")


if __name__ == "__main__":
    unittest.main()
