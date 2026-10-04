# MAVLink Honeypot

MAVLink tabanlı İnsansız Hava Aracı (İHA) sistemlerine yönelik siber saldırıları tespit etmek, loglamak ve analiz etmek için geliştirilmiş simüle honeypot backend ve dashboard projesi.

---

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
├── dashboard/                
│   ├── app.py                # Flask sunucusu
│   ├── templates/            # HTML şablonları
│   └── static/               # CSS, JS, grafik kütüphaneleri
└── tests/                    # Backend testleri
```

