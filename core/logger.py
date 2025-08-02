"""
Loglama sistemi
"""

import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional
from colorama import Fore, Style, init

# Colorama'yı başlat
init(autoreset=True)

class Logger:
    """Gelişmiş loglama sistemi"""
    
    def __init__(self, 
                 log_file: Optional[str] = None,
                 verbose: bool = False,
                 log_level: str = "INFO"):
        self.verbose = verbose
        self.log_level = getattr(logging, log_level.upper())
        
        # Logger'ı yapılandır
        self.logger = logging.getLogger("WirelessMeshAttack")
        self.logger.setLevel(self.log_level)
        
        # Mevcut handler'ları temizle
        self.logger.handlers.clear()
        
        # Console handler
        self._setup_console_handler()
        
        # File handler
        if log_file:
            self._setup_file_handler(log_file)
    
    def _setup_console_handler(self):
        """Console handler'ı ayarla"""
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(self.log_level)
        
        # Renkli format
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%H:%M:%S'
        )
        console_handler.setFormatter(formatter)
        
        self.logger.addHandler(console_handler)
    
    def _setup_file_handler(self, log_file: str):
        """Dosya handler'ı ayarla"""
        # Log dizinini oluştur
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(self.log_level)
        
        # Detaylı format
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
    
    def _log_with_color(self, level: str, message: str, color: str):
        """Renkli log mesajı"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        colored_message = f"{color}[{timestamp}] {level}: {message}{Style.RESET_ALL}"
        
        if level == "DEBUG" and not self.verbose:
            return
        
        print(colored_message)
        
        # Dosyaya da yaz (renksiz)
        self.logger.log(getattr(logging, level), message)
    
    def debug(self, message: str):
        """Debug mesajı"""
        self._log_with_color("DEBUG", message, Fore.CYAN)
    
    def info(self, message: str):
        """Bilgi mesajı"""
        self._log_with_color("INFO", message, Fore.WHITE)
    
    def success(self, message: str):
        """Başarı mesajı"""
        self._log_with_color("INFO", f"✓ {message}", Fore.GREEN)
    
    def warning(self, message: str):
        """Uyarı mesajı"""
        self._log_with_color("WARNING", f"⚠ {message}", Fore.YELLOW)
    
    def error(self, message: str):
        """Hata mesajı"""
        self._log_with_color("ERROR", f"✗ {message}", Fore.RED)
    
    def critical(self, message: str):
        """Kritik hata mesajı"""
        self._log_with_color("CRITICAL", f"💥 {message}", Fore.RED + Style.BRIGHT)
    
    def attack(self, message: str):
        """Saldırı mesajı"""
        self._log_with_color("INFO", f"🔴 {message}", Fore.RED)
    
    def target(self, message: str):
        """Hedef mesajı"""
        self._log_with_color("INFO", f"🎯 {message}", Fore.MAGENTA)
    
    def network(self, message: str):
        """Ağ mesajı"""
        self._log_with_color("INFO", f"🌐 {message}", Fore.BLUE)
    
    def stealth(self, message: str):
        """Gizlilik mesajı"""
        self._log_with_color("INFO", f"👻 {message}", Fore.CYAN)
    
    def mapping(self, message: str):
        """Haritalandırma mesajı"""
        self._log_with_color("INFO", f"🗺️ {message}", Fore.GREEN)
    
    def progress(self, current: int, total: int, description: str = ""):
        """İlerleme çubuğu"""
        percentage = (current / total) * 100
        bar_length = 30
        filled_length = int(bar_length * current // total)
        
        bar = '█' * filled_length + '-' * (bar_length - filled_length)
        
        message = f"{description} [{bar}] {percentage:.1f}% ({current}/{total})"
        self._log_with_color("INFO", message, Fore.BLUE)
    
    def table(self, headers: list, rows: list, title: str = ""):
        """Tablo formatında log"""
        if title:
            self.info(f"📊 {title}")
        
        # Tablo başlığı
        header_str = " | ".join(str(h) for h in headers)
        self.info(f"┌{'─' * len(header_str)}┐")
        self.info(f"│ {header_str} │")
        self.info(f"├{'─' * len(header_str)}┤")
        
        # Tablo satırları
        for row in rows:
            row_str = " | ".join(str(cell) for cell in row)
            self.info(f"│ {row_str} │")
        
        self.info(f"└{'─' * len(header_str)}┘")
    
    def banner(self, title: str = "Wireless Mesh Attack Framework"):
        """Banner yazdır"""
        banner = f"""
{Fore.RED}╔══════════════════════════════════════════════════════════════╗
║{Fore.WHITE}                    {title}{Fore.RED}                    ║
║{Fore.WHITE}              Advanced Wireless Attack Automation{Fore.RED}              ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
        """
        print(banner)
    
    def section(self, title: str):
        """Bölüm başlığı"""
        self.info(f"\n{Fore.YELLOW}═══ {title} ═══{Style.RESET_ALL}")
    
    def subsection(self, title: str):
        """Alt bölüm başlığı"""
        self.info(f"\n{Fore.CYAN}─── {title} ───{Style.RESET_ALL}")
    
    def separator(self):
        """Ayırıcı çizgi"""
        self.info(f"{Fore.BLUE}{'─' * 60}{Style.RESET_ALL}")
    
    def log_attack_event(self, 
                        attack_type: str, 
                        target: str, 
                        success: bool, 
                        details: dict = None):
        """Saldırı olayını logla"""
        status = "BAŞARILI" if success else "BAŞARISIZ"
        color = Fore.GREEN if success else Fore.RED
        
        self.attack(f"Saldırı: {attack_type} → {target} ({status})")
        
        if details and self.verbose:
            for key, value in details.items():
                self.debug(f"  {key}: {value}")
    
    def log_target_discovery(self, target: dict):
        """Hedef keşfini logla"""
        self.target(f"Yeni hedef keşfedildi: {target.get('name', 'Unknown')}")
        self.debug(f"  IP: {target.get('ip', 'Unknown')}")
        self.debug(f"  MAC: {target.get('mac', 'Unknown')}")
        self.debug(f"  Tür: {target.get('type', 'Unknown')}")
        self.debug(f"  Güvenlik Skoru: {target.get('security_score', 'Unknown')}")
    
    def log_network_scan(self, networks: list):
        """Ağ tarama sonuçlarını logla"""
        self.network(f"{len(networks)} ağ bulundu")
        
        if self.verbose:
            for network in networks:
                self.debug(f"  SSID: {network.get('ssid', 'Unknown')}")
                self.debug(f"  BSSID: {network.get('bssid', 'Unknown')}")
                self.debug(f"  Güç: {network.get('signal_strength', 'Unknown')}")
                self.debug(f"  Şifreleme: {network.get('encryption', 'Unknown')}")
    
    def log_stealth_action(self, action: str, details: str = ""):
        """Gizlilik aksiyonunu logla"""
        self.stealth(f"{action}: {details}")
    
    def log_mapping_update(self, devices_count: int, connections_count: int):
        """Haritalandırma güncellemesini logla"""
        self.mapping(f"Harita güncellendi: {devices_count} cihaz, {connections_count} bağlantı")
    
    def cleanup(self):
        """Logger'ı temizle"""
        for handler in self.logger.handlers[:]:
            handler.close()
            self.logger.removeHandler(handler) 