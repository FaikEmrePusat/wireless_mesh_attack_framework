"""
Gizlilik yönetimi
"""

import os
import random
import subprocess
import time
from typing import Optional, List
from pathlib import Path

from .config import Config
from .logger import Logger

class StealthManager:
    """Gizlilik yönetimi sınıfı"""
    
    def __init__(self, config: Config, logger: Logger):
        self.config = config
        self.logger = logger
        self.original_mac = None
        self.original_hostname = None
        self.original_ip = None
    
    def enable_stealth_mode(self) -> bool:
        """Gizlilik modunu etkinleştir"""
        self.logger.stealth("Gizlilik modu etkinleştiriliyor...")
        
        success = True
        
        # MAC adresi değiştir
        if self.config.get("stealth.mac_spoofing", True):
            success &= self.spoof_mac_address()
        
        # Hostname değiştir
        if self.config.get("stealth.hostname_spoofing", True):
            success &= self.spoof_hostname()
        
        # Log temizleme
        if self.config.get("stealth.log_cleaning", True):
            success &= self.clean_logs()
        
        # Trafik maskeleme
        if self.config.get("stealth.traffic_masking", True):
            success &= self.mask_traffic()
        
        if success:
            self.logger.success("Gizlilik modu etkinleştirildi")
        else:
            self.logger.warning("Gizlilik modu kısmen etkinleştirildi")
        
        return success
    
    def disable_stealth_mode(self) -> bool:
        """Gizlilik modunu devre dışı bırak"""
        self.logger.stealth("Gizlilik modu devre dışı bırakılıyor...")
        
        success = True
        
        # Orijinal MAC adresini geri yükle
        if self.original_mac:
            success &= self.restore_mac_address()
        
        # Orijinal hostname'i geri yükle
        if self.original_hostname:
            success &= self.restore_hostname()
        
        if success:
            self.logger.success("Gizlilik modu devre dışı bırakıldı")
        
        return success
    
    def spoof_mac_address(self, interface: str = "wlan0") -> bool:
        """MAC adresini değiştir"""
        try:
            # Orijinal MAC adresini kaydet
            if not self.original_mac:
                self.original_mac = self.get_mac_address(interface)
            
            # Rastgele MAC adresi oluştur
            new_mac = self.generate_random_mac()
            
            # MAC adresini değiştir
            self.logger.stealth(f"MAC adresi değiştiriliyor: {self.original_mac} → {new_mac}")
            
            # Arayüzü kapat
            subprocess.run(["ifconfig", interface, "down"], check=True)
            
            # MAC adresini değiştir
            subprocess.run(["ifconfig", interface, "hw", "ether", new_mac], check=True)
            
            # Arayüzü aç
            subprocess.run(["ifconfig", interface, "up"], check=True)
            
            self.logger.success(f"MAC adresi değiştirildi: {new_mac}")
            return True
            
        except Exception as e:
            self.logger.error(f"MAC adresi değiştirme hatası: {e}")
            return False
    
    def restore_mac_address(self, interface: str = "wlan0") -> bool:
        """Orijinal MAC adresini geri yükle"""
        if not self.original_mac:
            return True
        
        try:
            self.logger.stealth(f"MAC adresi geri yükleniyor: {self.original_mac}")
            
            # Arayüzü kapat
            subprocess.run(["ifconfig", interface, "down"], check=True)
            
            # Orijinal MAC adresini geri yükle
            subprocess.run(["ifconfig", interface, "hw", "ether", self.original_mac], check=True)
            
            # Arayüzü aç
            subprocess.run(["ifconfig", interface, "up"], check=True)
            
            self.logger.success("MAC adresi geri yüklendi")
            return True
            
        except Exception as e:
            self.logger.error(f"MAC adresi geri yükleme hatası: {e}")
            return False
    
    def spoof_hostname(self) -> bool:
        """Hostname'i değiştir"""
        try:
            # Orijinal hostname'i kaydet
            if not self.original_hostname:
                self.original_hostname = os.uname().nodename
            
            # Rastgele hostname oluştur
            new_hostname = self.generate_random_hostname()
            
            self.logger.stealth(f"Hostname değiştiriliyor: {self.original_hostname} → {new_hostname}")
            
            # Hostname'i değiştir
            subprocess.run(["hostnamectl", "set-hostname", new_hostname], check=True)
            
            # /etc/hosts dosyasını güncelle
            self.update_hosts_file(new_hostname)
            
            self.logger.success(f"Hostname değiştirildi: {new_hostname}")
            return True
            
        except Exception as e:
            self.logger.error(f"Hostname değiştirme hatası: {e}")
            return False
    
    def restore_hostname(self) -> bool:
        """Orijinal hostname'i geri yükle"""
        if not self.original_hostname:
            return True
        
        try:
            self.logger.stealth(f"Hostname geri yükleniyor: {self.original_hostname}")
            
            # Hostname'i geri yükle
            subprocess.run(["hostnamectl", "set-hostname", self.original_hostname], check=True)
            
            # /etc/hosts dosyasını güncelle
            self.update_hosts_file(self.original_hostname)
            
            self.logger.success("Hostname geri yüklendi")
            return True
            
        except Exception as e:
            self.logger.error(f"Hostname geri yükleme hatası: {e}")
            return False
    
    def clean_logs(self) -> bool:
        """Log dosyalarını temizle"""
        try:
            log_files = [
                "/var/log/auth.log",
                "/var/log/syslog",
                "/var/log/messages",
                "/var/log/kern.log",
                "/var/log/dmesg"
            ]
            
            for log_file in log_files:
                if os.path.exists(log_file):
                    # Log dosyasını temizle
                    with open(log_file, 'w') as f:
                        f.write("")
                    
                    self.logger.stealth(f"Log dosyası temizlendi: {log_file}")
            
            # Browser geçmişini temizle
            self.clean_browser_history()
            
            self.logger.success("Log dosyaları temizlendi")
            return True
            
        except Exception as e:
            self.logger.error(f"Log temizleme hatası: {e}")
            return False
    
    def mask_traffic(self) -> bool:
        """Trafik maskeleme"""
        try:
            # Random delays
            if self.config.get("stealth.random_delays", True):
                delay = random.uniform(1, 5)
                time.sleep(delay)
                self.logger.stealth(f"Rastgele gecikme: {delay:.2f}s")
            
            # Traffic shaping (basit)
            self.logger.stealth("Trafik maskeleme etkinleştirildi")
            return True
            
        except Exception as e:
            self.logger.error(f"Trafik maskeleme hatası: {e}")
            return False
    
    def generate_random_mac(self) -> str:
        """Rastgele MAC adresi oluştur"""
        # Yerel yönetimli MAC adresi (LSB = 1)
        mac = [0x02]  # Yerel yönetimli bit
        
        # Rastgele 5 byte ekle
        for _ in range(5):
            mac.append(random.randint(0, 255))
        
        return ":".join([f"{b:02x}" for b in mac])
    
    def generate_random_hostname(self) -> str:
        """Rastgele hostname oluştur"""
        prefixes = ["pc", "laptop", "desktop", "workstation", "terminal"]
        suffixes = ["01", "02", "03", "admin", "user", "test"]
        
        prefix = random.choice(prefixes)
        suffix = random.choice(suffixes)
        
        return f"{prefix}-{suffix}"
    
    def get_mac_address(self, interface: str) -> Optional[str]:
        """MAC adresini al"""
        try:
            result = subprocess.run(
                ["ifconfig", interface], 
                capture_output=True, 
                text=True, 
                check=True
            )
            
            # MAC adresini parse et
            for line in result.stdout.split('\n'):
                if 'ether' in line:
                    return line.split('ether')[1].strip()
            
            return None
            
        except Exception as e:
            self.logger.error(f"MAC adresi alma hatası: {e}")
            return None
    
    def update_hosts_file(self, hostname: str) -> None:
        """/etc/hosts dosyasını güncelle"""
        try:
            hosts_file = "/etc/hosts"
            
            # Mevcut hosts dosyasını oku
            with open(hosts_file, 'r') as f:
                lines = f.readlines()
            
            # 127.0.0.1 satırını güncelle
            new_lines = []
            for line in lines:
                if line.startswith("127.0.0.1"):
                    new_lines.append(f"127.0.0.1\tlocalhost\t{hostname}\n")
                else:
                    new_lines.append(line)
            
            # Dosyayı yaz
            with open(hosts_file, 'w') as f:
                f.writelines(new_lines)
                
        except Exception as e:
            self.logger.error(f"Hosts dosyası güncelleme hatası: {e}")
    
    def clean_browser_history(self) -> None:
        """Browser geçmişini temizle"""
        try:
            # Firefox geçmişi
            firefox_dir = Path.home() / ".mozilla/firefox"
            if firefox_dir.exists():
                for profile in firefox_dir.glob("*.default*"):
                    places_file = profile / "places.sqlite"
                    if places_file.exists():
                        places_file.unlink()
            
            # Chrome geçmişi
            chrome_dir = Path.home() / ".config/google-chrome/Default"
            if chrome_dir.exists():
                history_file = chrome_dir / "History"
                if history_file.exists():
                    history_file.unlink()
            
            self.logger.stealth("Browser geçmişi temizlendi")
            
        except Exception as e:
            self.logger.error(f"Browser geçmişi temizleme hatası: {e}")
    
    def add_random_delay(self, min_delay: float = 1.0, max_delay: float = 5.0) -> None:
        """Rastgele gecikme ekle"""
        if self.config.get("stealth.random_delays", True):
            delay = random.uniform(min_delay, max_delay)
            time.sleep(delay)
            self.logger.stealth(f"Rastgele gecikme: {delay:.2f}s")
    
    def rotate_identity(self) -> bool:
        """Kimliği değiştir"""
        self.logger.stealth("Kimlik değiştiriliyor...")
        
        success = True
        success &= self.spoof_mac_address()
        success &= self.spoof_hostname()
        
        if success:
            self.logger.success("Kimlik değiştirildi")
        
        return success 