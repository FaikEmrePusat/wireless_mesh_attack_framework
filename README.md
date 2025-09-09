# Wireless Mesh Attack Framework

Gelişmiş kablosuz saldırı otomasyonu ve mesh ağ saldırı sistemi.

## Proje Hakkında

Wireless Mesh Attack Framework, kablosuz ağlarda otomatik saldırı, pivoting ve yayılma işlemlerini gerçekleştiren gelişmiş bir Red Team aracıdır. Bu framework, bir cihazdan başlayarak tüm ağa yayılan otomatik saldırı zincirleri oluşturabilir.

## Uyarı

**Bu araç sadece eğitim ve yasal penetrasyon testleri için tasarlanmıştır. İzinsiz kullanım yasal değildir ve sorumluluk kullanıcıya aittir.**

## Özellikler

### Keşif ve Tarama
- **Wi-Fi Ağ Tarama**: Pasif ve aktif Wi-Fi ağ keşfi
- **Cihaz Keşfi**: Ağdaki cihazları otomatik tespit
- **Zafiyet Analizi**: Güvenlik skorlaması ve hedef önceliklendirme
- **Ağ Haritalandırma**: Topoloji analizi ve bağlantı haritası

### Saldırı Modülleri
- **WPA2 Handshake Capture**: WPA2 şifre kırma
- **Deauth Saldırısı**: Bağlantı kesme saldırıları
- **Evil Twin**: Sahte erişim noktası oluşturma
- **Web Exploit**: Modem web arayüzü saldırıları
- **Brute Force**: Şifre deneme saldırıları

### Pivoting ve Yayılma
- **ARP Spoofing**: Man-in-the-middle saldırıları
- **DNS Hijacking**: DNS yönlendirme saldırıları
- **Traffic Monitoring**: Ağ trafiği izleme
- **Port Scanning**: Port tarama ve servis keşfi

### Haritalandırma
- **Gerçek Zamanlı Harita**: Saldırı ağını görselleştirme
- **Koordinat Toplama**: GPS ve IP bazlı konum tespiti
- **Saldırı Rotaları**: Saldırı zincirlerini görselleştirme
- **İstatistikler**: Saldırı başarı oranları ve analizler

### Gizlilik
- **MAC Spoofing**: MAC adresi değiştirme
- **Hostname Spoofing**: Hostname değiştirme
- **Log Temizleme**: İz temizleme
- **Traffic Masking**: Trafik maskeleme

## Gereksinimler

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
