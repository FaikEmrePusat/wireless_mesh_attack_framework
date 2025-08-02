"""
Yardımcı fonksiyonlar
"""

import ipaddress
import re
import socket
import subprocess
from typing import Dict, List, Optional, Tuple
from pathlib import Path

class Utils:
    """Yardımcı fonksiyonlar sınıfı"""
    
    @staticmethod
    def detect_target_type(target: str) -> str:
        """Hedef türünü belirle"""
        # IP adresi kontrolü
        if Utils.is_valid_ip(target):
            return "ip"
        
        # SSID kontrolü (Wi-Fi ağı)
        if Utils.is_valid_ssid(target):
            return "ssid"
        
        # URL kontrolü
        if Utils.is_valid_url(target):
            return "web"
        
        # MAC adresi kontrolü
        if Utils.is_valid_mac(target):
            return "mac"
        
        # Modem kontrolü (varsayılan gateway'ler)
        if Utils.is_likely_modem(target):
            return "modem"
        
        return "unknown"
    
    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """IP adresi geçerliliğini kontrol et"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_valid_ssid(ssid: str) -> bool:
        """SSID geçerliliğini kontrol et"""
        # SSID 1-32 karakter olmalı
        if len(ssid) < 1 or len(ssid) > 32:
            return False
        
        # SSID sadece ASCII karakterler içermeli
        try:
            ssid.encode('ascii')
            return True
        except UnicodeEncodeError:
            return False
    
    @staticmethod
    def is_valid_url(url: str) -> bool:
        """URL geçerliliğini kontrol et"""
        url_pattern = re.compile(
            r'^https?://'  # http:// veya https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
            r'localhost|'  # localhost
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP
            r'(?::\d+)?'  # port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        return bool(url_pattern.match(url))
    
    @staticmethod
    def is_valid_mac(mac: str) -> bool:
        """MAC adresi geçerliliğini kontrol et"""
        mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
        return bool(mac_pattern.match(mac))
    
    @staticmethod
    def is_likely_modem(ip: str) -> bool:
        """IP'nin muhtemelen modem olduğunu kontrol et"""
        if not Utils.is_valid_ip(ip):
            return False
        
        # Yaygın modem IP'leri
        common_modem_ips = [
            "192.168.1.1",
            "192.168.0.1", 
            "192.168.2.1",
            "10.0.0.1",
            "10.0.1.1",
            "172.16.0.1",
            "172.16.1.1"
        ]
        
        return ip in common_modem_ips
    
    @staticmethod
    def get_network_range(ip: str, netmask: str = "255.255.255.0") -> List[str]:
        """IP ağındaki tüm IP'leri döndür"""
        try:
            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            return []
    
    @staticmethod
    def ping_host(ip: str, timeout: int = 1) -> bool:
        """Host'a ping at"""
        try:
            subprocess.run(
                ["ping", "-c", "1", "-W", str(timeout), ip],
                capture_output=True,
                check=True
            )
            return True
        except subprocess.CalledProcessError:
            return False
    
    @staticmethod
    def scan_port(ip: str, port: int, timeout: int = 1) -> bool:
        """Port taraması yap"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    @staticmethod
    def get_local_ip() -> Optional[str]:
        """Yerel IP adresini al"""
        try:
            # UDP socket ile dış bağlantı kur (gerçekten bağlanmaz)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return None
    
    @staticmethod
    def get_gateway_ip() -> Optional[str]:
        """Gateway IP adresini al"""
        try:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Gateway IP'sini parse et
            for line in result.stdout.split('\n'):
                if 'default via' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        return parts[2]
            
            return None
            
        except Exception:
            return None
    
    @staticmethod
    def find_device_by_id(device_id: str, devices: List[Dict]) -> Optional[Dict]:
        """Cihaz listesinden ID'ye göre cihaz bul"""
        for device in devices:
            if device.get('id') == device_id:
                return device
        return None
    
    @staticmethod
    def calculate_security_score(device: Dict) -> float:
        """Cihazın güvenlik skorunu hesapla"""
        score = 10.0  # Başlangıç skoru
        
        # Şifreleme türü
        encryption = device.get('encryption', '').lower()
        if 'wep' in encryption:
            score -= 7
        elif 'wpa' in encryption:
            score -= 3
        elif 'wpa2' in encryption:
            score -= 1
        elif 'wpa3' in encryption:
            score -= 0.5
        
        # Firmware yaşı
        firmware_age = device.get('firmware_age', 0)
        if firmware_age > 5:
            score -= 3
        elif firmware_age > 2:
            score -= 1
        
        # Açık portlar
        open_ports = device.get('open_ports', [])
        score -= len(open_ports) * 0.5
        
        # Default şifre
        if device.get('default_password', False):
            score -= 5
        
        # Root erişimi
        if device.get('root_access', False):
            score -= 2
        
        return max(0.0, score)
    
    @staticmethod
    def parse_nmap_output(output: str) -> List[Dict]:
        """Nmap çıktısını parse et"""
        devices = []
        
        # IP adresi ve MAC adresi pattern'i
        ip_mac_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})')
        
        for line in output.split('\n'):
            match = ip_mac_pattern.search(line)
            if match:
                ip, mac = match.groups()
                devices.append({
                    'ip': ip,
                    'mac': mac,
                    'type': 'unknown'
                })
        
        return devices
    
    @staticmethod
    def parse_arp_table(arp_output: str) -> List[Dict]:
        """ARP tablosunu parse et"""
        devices = []
        
        for line in arp_output.split('\n'):
            if 'ether' in line and 'incomplete' not in line:
                parts = line.split()
                if len(parts) >= 4:
                    ip = parts[0]
                    mac = parts[2]
                    devices.append({
                        'ip': ip,
                        'mac': mac,
                        'type': 'unknown'
                    })
        
        return devices
    
    @staticmethod
    def generate_device_id(device_info: Dict) -> str:
        """Cihaz ID'si oluştur"""
        # MAC adresinden ID oluştur
        if 'mac' in device_info:
            mac = device_info['mac'].replace(':', '').replace('-', '')
            return f"device_{mac[-6:]}"
        
        # IP adresinden ID oluştur
        if 'ip' in device_info:
            ip_parts = device_info['ip'].split('.')
            return f"device_{ip_parts[-2]}_{ip_parts[-1]}"
        
        # Rastgele ID oluştur
        import random
        return f"device_{random.randint(1000, 9999)}"
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Dosya adını temizle"""
        # Geçersiz karakterleri kaldır
        invalid_chars = '<>:"/\\|?*'
        for char in invalid_chars:
            filename = filename.replace(char, '_')
        
        # Boşlukları alt çizgi ile değiştir
        filename = filename.replace(' ', '_')
        
        # Çoklu alt çizgileri tek alt çizgi yap
        filename = re.sub(r'_+', '_', filename)
        
        return filename
    
    @staticmethod
    def ensure_directory(path: str) -> bool:
        """Dizinin var olduğundan emin ol"""
        try:
            Path(path).mkdir(parents=True, exist_ok=True)
            return True
        except Exception:
            return False
    
    @staticmethod
    def get_file_size(file_path: str) -> int:
        """Dosya boyutunu al"""
        try:
            return Path(file_path).stat().st_size
        except Exception:
            return 0
    
    @staticmethod
    def format_bytes(bytes_size: int) -> str:
        """Byte boyutunu okunabilir formata çevir"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.1f} {unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.1f} TB"
    
    @staticmethod
    def get_system_info() -> Dict[str, str]:
        """Sistem bilgilerini al"""
        info = {}
        
        try:
            # İşletim sistemi
            import platform
            info['os'] = platform.system()
            info['os_version'] = platform.release()
            
            # Hostname
            info['hostname'] = platform.node()
            
            # Python versiyonu
            info['python_version'] = platform.python_version()
            
            # CPU bilgisi
            info['cpu'] = platform.processor()
            
        except Exception:
            pass
        
        return info
    
    @staticmethod
    def check_dependencies() -> Dict[str, bool]:
        """Gerekli bağımlılıkları kontrol et"""
        dependencies = {
            'scapy': False,
            'nmap': False,
            'aircrack-ng': False,
            'tcpdump': False,
            'iw': False
        }
        
        try:
            import scapy
            dependencies['scapy'] = True
        except ImportError:
            pass
        
        # Sistem komutlarını kontrol et
        for cmd in ['nmap', 'aircrack-ng', 'tcpdump', 'iw']:
            try:
                subprocess.run([cmd, '--version'], capture_output=True, check=True)
                dependencies[cmd] = True
            except (subprocess.CalledProcessError, FileNotFoundError):
                pass
        
        return dependencies 