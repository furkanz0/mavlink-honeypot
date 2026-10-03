# MAVLink Honeypot

MAVLink tabanlı İnsansız Hava Aracı (İHA) sistemlerine yönelik siber saldırıları tespit etmek, loglamak ve analiz etmek için geliştirilmiş simüle honeypot backend ve dashboard projesi.

---

## 📌 Proje Mimarisi ve Ekip İş Bölümü

Bu proje iki ana bileşenden oluşur ve iki kişi arasında gevşek bağlı (loosely coupled) bir mimari ile paylaşılmıştır:

1. **Kişi 1 (Backend Ekibi):**
   - UDP (Port 14550) ve TCP (Port 14551) MAVLink Dinleyicileri
   - Paket Ayrıştırıcı (`mavlink_handler.py`)
   - İmza ve Kural Tabanlı Sınıflandırıcı (`event_classifier.py`)
   - Durum ve Davranış Analizörü (`behavior_analyzer.py`)
   - Sahte Yanıt Üretici (`mavlink_responder.py`)
   - Olay Kaydedici (`event_logger.py`) → `events.json` üretimi

2. **Kişi 2 (Frontend / Dashboard Ekibi):**
   - Web Arayüzü / Dashboard (Flask, HTML/CSS/JS)
   - `events.json` dosyasını periyodik/canlı okuyarak görselleştirme
   - İstatistikler: Toplam saldırı, normal/şüpheli oranları, kaynak IP'ler, mesaj türleri, protokol dağılımı (UDP vs TCP), zaman serisi grafikleri

---

## ⚠️ DEĞİŞTİRİLEMEZ ORTAK SÖZLEŞME (CONTRACT)

> **Kural:** `events.json` dosyası, Backend ile Dashboard arasındaki **TEK** veri kaynağı ve köprüdür.
> - Backend hiçbir şekilde Flask veya dashboard modüllerini `import` etmez.
> - Dashboard hiçbir şekilde backend Python dosyalarını (`server.py`, `behavior_analyzer.py` vb.) `import` etmez.
> - Dashboard yalnızca `events.json` dosyasını JSON olarak okur.

### `events.json` Veri Yapısı

Her bir olay (event) **tam olarak 6 alana** sahiptir:

```json
[
  {
    "timestamp": "2026-10-03 12:54:28",
    "source_ip": "127.0.0.1",
    "source_port": 61588,
    "protocol": "UDP",
    "message_type": "HEARTBEAT",
    "status": "NORMAL"
  },
  {
    "timestamp": "2026-10-03 12:54:30",
    "source_ip": "192.168.1.105",
    "source_port": 54321,
    "protocol": "TCP",
    "message_type": "COMMAND_LONG",
    "status": "SUSPICIOUS"
  }
]
```

### Alan Detayları:
| Alan Adı | Tip | Açıklama |
|---|---|---|
| `timestamp` | String | `YYYY-MM-DD HH:MM:SS` formatında tarih/saat |
| `source_ip` | String | İstemci IP adresi (örn: `"127.0.0.1"`) |
| `source_port`| Integer | İstemci port numarası (örn: `54321`) |
| `protocol` | String | `"UDP"` veya `"TCP"` |
| `message_type` | String | MAVLink mesaj tipi (örn: `"HEARTBEAT"`, `"COMMAND_LONG"`, `"UNKNOWN"`) |
| `status` | String | `"NORMAL"` veya `"SUSPICIOUS"` |

---

## 🚀 Kurulum (Kişi 2 ve Geliştiriciler İçin)

### 1. Depoyu Klonlayın
```bash
git clone <REPO_URL>
cd mavlink-honeypot
```

### 2. Sanal Ortam (Virtual Environment) Oluşturun ve Aktif Edin
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### 3. Bağımlılıkları Yükleyin
```bash
pip install -r requirements.txt
```

*(Kişi 2 dashboard için Flask, Chart.js vb. kullanacaksa kendi bağımlılıklarını requirements.txt'ye ekleyebilir.)*

---

## 💻 Çalıştırma

### Backend Sunucularını Başlatma

- **UDP Sunucusu (Port 14550):**
  ```bash
  python server.py
  ```

- **TCP Sunucusu (Port 14551):**
  ```bash
  python tcp_server.py
  ```

### Dashboard'u (Web Arayüzü) Başlatma

- **Flask Dashboard:**
  ```bash
  python dashboard/app.py
  ```
  Tarayıcınızdan [http://127.0.0.1:5000](http://127.0.0.1:5000) adresine giderek güvenlik panelini canlı olarak inceleyebilirsiniz.

### Simülasyon / Test İstemcilerini Çalıştırma

- **UDP Trafik Testi (Normal & Şüpheli paketler):**
  ```bash
  python tests/test_client.py
  ```

- **TCP Trafik Testi:**
  ```bash
  python tests/tcp_test_client.py
  ```

### Otomatik Testleri Koşturma

Tüm birim, entegrasyon ve end-to-end testleri çalıştırmak için:
```bash
pytest -v
```
*(Toplam 62 test mevcuttur; tüm backend bileşenleri, TCP/UDP stabilite, yük ve dashboard testlerini kapsar.)*

---

## 🎨 Kişi 2 (Dashboard) İçin Rehber

Kişi 2 dashboard kodlarını projenin kök dizininde ayrı bir klasörde (örneğin `dashboard/`) geliştirebilir:

```
mavlink-honeypot/
├── behavior_analyzer.py      # Backend
├── event_classifier.py       # Backend
├── event_logger.py           # Backend
├── event_validator.py        # Backend
├── mavlink_handler.py        # Backend
├── mavlink_responder.py      # Backend
├── server.py                 # UDP Server
├── tcp_server.py             # TCP Server
├── events.json               # Ortak veri kaynağı (Dashboard buradan okur)
├── dashboard/                # Kişi 2'nin çalışma alanı
│   ├── app.py                # Flask sunucusu
│   ├── templates/            # HTML şablonları
│   └── static/               # CSS, JS, grafik kütüphaneleri
└── tests/                    # Backend testleri
```

Kişi 2, `events.json` dosyasını `with open("../events.json", "r", encoding="utf-8") as f: events = json.load(f)` şeklinde güvenle okuyabilir.
Dosya başlangıçta örnek veri içermektedir; böylece backend çalışmasa dahi dashboard hemen test edilebilir.
