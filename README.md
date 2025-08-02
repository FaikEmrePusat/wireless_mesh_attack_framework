# Wireless Mesh Attack Framework

Gelişmiş kablosuz saldırı otomasyonu ve mesh ağ saldırı sistemi.

## 🎯 Proje Hakkında

Wireless Mesh Attack Framework, kablosuz ağlarda otomatik saldırı, pivoting ve yayılma işlemlerini gerçekleştiren gelişmiş bir Red Team aracıdır. Bu framework, bir cihazdan başlayarak tüm ağa yayılan otomatik saldırı zincirleri oluşturabilir.

## ⚠️ Uyarı

**Bu araç sadece eğitim ve yasal penetrasyon testleri için tasarlanmıştır. İzinsiz kullanım yasal değildir ve sorumluluk kullanıcıya aittir.**

## 🚀 Özellikler

### 🔍 Keşif ve Tarama
- **Wi-Fi Ağ Tarama**: Pasif ve aktif Wi-Fi ağ keşfi
- **Cihaz Keşfi**: Ağdaki cihazları otomatik tespit
- **Zafiyet Analizi**: Güvenlik skorlaması ve hedef önceliklendirme
- **Ağ Haritalandırma**: Topoloji analizi ve bağlantı haritası

### 🔴 Saldırı Modülleri
- **WPA2 Handshake Capture**: WPA2 şifre kırma
- **Deauth Saldırısı**: Bağlantı kesme saldırıları
- **Evil Twin**: Sahte erişim noktası oluşturma
- **Web Exploit**: Modem web arayüzü saldırıları
- **Brute Force**: Şifre deneme saldırıları

### 🔄 Pivoting ve Yayılma
- **ARP Spoofing**: Man-in-the-middle saldırıları
- **DNS Hijacking**: DNS yönlendirme saldırıları
- **Traffic Monitoring**: Ağ trafiği izleme
- **Port Scanning**: Port tarama ve servis keşfi

### 🗺️ Haritalandırma
- **Gerçek Zamanlı Harita**: Saldırı ağını görselleştirme
- **Koordinat Toplama**: GPS ve IP bazlı konum tespiti
- **Saldırı Rotaları**: Saldırı zincirlerini görselleştirme
- **İstatistikler**: Saldırı başarı oranları ve analizler

### 👻 Gizlilik
- **MAC Spoofing**: MAC adresi değiştirme
- **Hostname Spoofing**: Hostname değiştirme
- **Log Temizleme**: İz temizleme
- **Traffic Masking**: Trafik maskeleme

## 📋 Gereksinimler

### Sistem Gereksinimleri
- Linux (Kali Linux önerilir)
- Python 3.8+
- Root yetkisi (bazı modüller için)

### Python Bağımlılıkları
```bash
pip install -r requirements.txt
```

### Sistem Araçları
- aircrack-ng
- nmap
- tcpdump
- iw
- hostapd

## 🛠️ Kurulum

### 1. Repository'yi Klonlayın
```bash
git clone https://github.com/your-username/wireless-mesh-attack-framework.git
cd wireless-mesh-attack-framework
```

### 2. Bağımlılıkları Yükleyin
```bash
# Python bağımlılıkları
pip install -r requirements.txt

# Sistem araçları (Ubuntu/Debian)
sudo apt update
sudo apt install aircrack-ng nmap tcpdump iw hostapd

# Sistem araçları (Kali Linux)
sudo apt update
sudo apt install aircrack-ng nmap tcpdump iw hostapd
```

### 3. Konfigürasyon
```bash
# Varsayılan konfigürasyon otomatik oluşturulur
python main.py --help
```

## 🎮 Kullanım

### Temel Kullanım

#### 1. Wi-Fi Ağlarını Tara
```bash
python main.py --mode scan --interface wlan0
```

#### 2. Hedef Saldırısı
```bash
python main.py --mode attack --target "192.168.1.1" --interface wlan0
```

#### 3. Pivoting
```bash
python main.py --mode pivot --device "modem_001"
```

#### 4. Saldırı Haritası
```bash
python main.py --mode map --output "attack_map.html"
```

#### 5. C2 Sunucusu
```bash
python main.py --mode c2
```

### Gelişmiş Kullanım

#### Otomatik Saldırı Döngüsü
```python
from core.main import WirelessMeshAttackFramework
from core.config import Config
from core.logger import Logger

# Framework'ü başlat
config = Config()
logger = Logger(verbose=True)
framework = WirelessMeshAttackFramework(config, logger)

# Otomatik saldırıyı başlat
framework.start_automated_attack()

# İstatistikleri al
stats = framework.get_statistics()
print(f"Ele geçirilen cihazlar: {stats['compromised_devices']}")
```

#### Plugin Geliştirme
```python
from core.plugin_manager import BasePlugin

class CustomAttack(BasePlugin):
    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.name = "CustomAttack"
        self.description = "Özel saldırı modülü"
    
    def execute(self, target):
        # Saldırı kodunuz burada
        self.logger.info(f"Hedef saldırılıyor: {target}")
        return True
```

## 📁 Proje Yapısı

```
wireless_mesh_attack_framework/
├── core/                   # Ana framework bileşenleri
├── plugins/                # Saldırı modülleri
│   ├── reconnaissance/     # Keşif modülleri
│   ├── attacks/           # Saldırı modülleri
│   ├── pivoting/          # Pivoting modülleri
│   └── device_specific/   # Cihaz özel modüller
├── mapping/               # Haritalandırma
├── c2_panel/              # Command & Control
├── web_interface/         # Web arayüzü
├── data/                  # Veri saklama
├── payloads/              # Payload'lar
└── docs/                  # Dokümantasyon
```

## 🔧 Konfigürasyon

### Ana Konfigürasyon Dosyası
```json
{
  "general": {
    "debug": false,
    "verbose": false,
    "stealth_mode": true
  },
  "network": {
    "default_interface": "wlan0",
    "monitor_mode": true
  },
  "attacks": {
    "wpa2_timeout": 300,
    "deauth_packets": 10
  },
  "stealth": {
    "mac_spoofing": true,
    "log_cleaning": true
  }
}
```

## 📊 Örnek Çıktılar

### Wi-Fi Tarama Sonucu
```
[INFO] Wi-Fi ağları taranıyor... (Arayüz: wlan0, Süre: 30s)
[SUCCESS] 15 Wi-Fi ağı bulundu

┌─────────────────────────────────────────────────────────────┐
│ SSID                │ BSSID           │ Kanal │ Şifreleme │
├─────────────────────────────────────────────────────────────┤
│ Komşu1_WiFi         │ 00:11:22:33:44:55│ 6     │ WPA2     │
│ iPhone_Hotspot      │ AA:BB:CC:DD:EE:FF│ 11    │ WPA2     │
│ Kamera_Net          │ 12:34:56:78:9A:BC│ 1     │ WEP      │
└─────────────────────────────────────────────────────────────┘
```

### Saldırı Haritası
- **Kırmızı noktalar**: Ele geçirilmiş cihazlar
- **Turuncu noktalar**: Hedef cihazlar
- **Yeşil noktalar**: Güvenli cihazlar
- **Mavi çizgiler**: Saldırı bağlantıları

## 🤝 Katkıda Bulunma

1. Fork yapın
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Commit yapın (`git commit -m 'Add amazing feature'`)
4. Push yapın (`git push origin feature/amazing-feature`)
5. Pull Request oluşturun

## 📝 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için `LICENSE` dosyasına bakın.

## ⚖️ Yasal Uyarı

Bu araç sadece:
- Kendi ağlarınızda test amaçlı
- İzinli penetrasyon testlerinde
- Eğitim amaçlı

kullanılmalıdır. İzinsiz kullanım yasal değildir.

## 📞 İletişim

- **GitHub**: [@your-username](https://github.com/your-username)
- **Email**: your-email@example.com

## 🙏 Teşekkürler

- [Scapy](https://scapy.net/) - Paket manipülasyonu
- [Aircrack-ng](https://www.aircrack-ng.org/) - Wi-Fi güvenlik araçları
- [Nmap](https://nmap.org/) - Ağ keşif
- [Folium](https://python-visualization.github.io/folium/) - Harita görselleştirme

---

**⚠️ Bu araç sadece eğitim amaçlıdır. Sorumlu kullanın!** 