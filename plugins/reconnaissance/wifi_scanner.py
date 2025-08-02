"""
Wi-Fi tarama modülü
"""

import subprocess
import re
import time
from typing import List, Dict, Optional
from scapy.all import *

from core.plugin_manager import BasePlugin
from core.config import Config
from core.logger import Logger

class WiFiScanner(BasePlugin):
    """Wi-Fi ağ tarama modülü"""
    
    def __init__(self, config: Config, logger: Logger):
        super().__init__(config, logger)
        self.name = "WiFiScanner"
        self.version = "1.0.0"
        self.description = "Wi-Fi ağları tarama ve keşif"
    
    def setup(self) -> bool:
        """Modül kurulumu"""
        try:
            # Monitor mode kontrolü
            if not self.check_monitor_mode():
                self.logger.warning("Monitor mode aktif değil")
            
            return True
        except Exception as e:
            self.logger.error(f"WiFiScanner kurulum hatası: {e}")
            return False
    
    def execute(self, interface: str = "wlan0", timeout: int = 30) -> List[Dict]:
        """Wi-Fi ağlarını tara"""
        return self.scan_networks(interface, timeout)
    
    def scan_networks(self, interface: str = "wlan0", timeout: int = 30) -> List[Dict]:
        """Wi-Fi ağlarını tara"""
        self.logger.info(f"Wi-Fi ağları taranıyor... (Arayüz: {interface}, Süre: {timeout}s)")
        
        networks = []
        
        try:
            # Scapy ile pasif tarama
            networks.extend(self.passive_scan(interface, timeout))
            
            # iwlist ile aktif tarama
            networks.extend(self.active_scan(interface))
            
            # Tekrarları kaldır
            networks = self.remove_duplicates(networks)
            
            # Güvenlik skorlarını hesapla
            for network in networks:
                network['security_score'] = self.calculate_security_score(network)
            
            # Güvenlik skoruna göre sırala (en zayıftan başla)
            networks.sort(key=lambda x: x.get('security_score', 10))
            
            self.logger.success(f"{len(networks)} Wi-Fi ağı bulundu")
            
            # Sonuçları tablo halinde göster
            self.display_networks(networks)
            
            return networks
            
        except Exception as e:
            self.logger.error(f"Wi-Fi tarama hatası: {e}")
            return []
    
    def passive_scan(self, interface: str, timeout: int) -> List[Dict]:
        """Pasif tarama (Scapy ile)"""
        networks = []
        
        try:
            self.logger.debug("Pasif tarama başlatılıyor...")
            
            def packet_handler(pkt):
                if pkt.haslayer(Dot11Beacon):
                    # Beacon paketini analiz et
                    network = self.parse_beacon_packet(pkt)
                    if network:
                        networks.append(network)
            
            # Paketleri dinle
            sniff(iface=interface, prn=packet_handler, timeout=timeout)
            
            self.logger.debug(f"Pasif tarama tamamlandı: {len(networks)} ağ")
            
        except Exception as e:
            self.logger.error(f"Pasif tarama hatası: {e}")
        
        return networks
    
    def active_scan(self, interface: str) -> List[Dict]:
        """Aktif tarama (iwlist ile)"""
        networks = []
        
        try:
            self.logger.debug("Aktif tarama başlatılıyor...")
            
            # iwlist komutu ile tarama
            result = subprocess.run(
                ["iwlist", interface, "scan"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                networks = self.parse_iwlist_output(result.stdout)
            
            self.logger.debug(f"Aktif tarama tamamlandı: {len(networks)} ağ")
            
        except Exception as e:
            self.logger.error(f"Aktif tarama hatası: {e}")
        
        return networks
    
    def parse_beacon_packet(self, pkt) -> Optional[Dict]:
        """Beacon paketini parse et"""
        try:
            # SSID
            ssid = None
            if pkt.haslayer(Dot11Elt):
                for elt in pkt[Dot11Elt]:
                    if elt.ID == 0:  # SSID
                        try:
                            ssid = elt.info.decode('utf-8')
                            if not ssid:  # Boş SSID
                                ssid = "<hidden>"
                        except UnicodeDecodeError:
                            ssid = "<hidden>"
                        break
            
            # BSSID
            bssid = pkt[Dot11].addr3
            
            # Sinyal gücü
            signal_strength = None
            if pkt.haslayer(RadioTap):
                signal_strength = pkt[RadioTap].dBm_AntSignal
            
            # Kanal
            channel = None
            if pkt.haslayer(Dot11Elt):
                for elt in pkt[Dot11Elt]:
                    if elt.ID == 3:  # DS Parameter Set
                        channel = elt.info[0]
                        break
            
            # Şifreleme
            encryption = self.detect_encryption(pkt)
            
            # WPS
            wps_enabled = self.detect_wps(pkt)
            
            return {
                'ssid': ssid,
                'bssid': bssid,
                'channel': channel,
                'signal_strength': signal_strength,
                'encryption': encryption,
                'wps_enabled': wps_enabled,
                'type': 'wifi_network',
                'discovery_method': 'passive'
            }
            
        except Exception as e:
            self.logger.debug(f"Beacon paket parse hatası: {e}")
            return None
    
    def parse_iwlist_output(self, output: str) -> List[Dict]:
        """iwlist çıktısını parse et"""
        networks = []
        
        try:
            # Cell bloklarını bul
            cell_blocks = re.findall(r'Cell \d+ - Address: ([0-9A-Fa-f:]+)(.*?)(?=Cell \d+|$)', 
                                   output, re.DOTALL)
            
            for bssid, block in cell_blocks:
                network = {
                    'bssid': bssid,
                    'type': 'wifi_network',
                    'discovery_method': 'active'
                }
                
                # SSID
                ssid_match = re.search(r'ESSID:"([^"]*)"', block)
                if ssid_match:
                    ssid = ssid_match.group(1)
                    network['ssid'] = ssid if ssid else "<hidden>"
                
                # Kanal
                channel_match = re.search(r'Channel:(\d+)', block)
                if channel_match:
                    network['channel'] = int(channel_match.group(1))
                
                # Sinyal gücü
                signal_match = re.search(r'Signal level=([-\d]+)', block)
                if signal_match:
                    network['signal_strength'] = int(signal_match.group(1))
                
                # Şifreleme
                if 'WPA' in block:
                    network['encryption'] = 'WPA/WPA2'
                elif 'WEP' in block:
                    network['encryption'] = 'WEP'
                else:
                    network['encryption'] = 'Open'
                
                # WPS
                network['wps_enabled'] = 'WPS' in block
                
                networks.append(network)
                
        except Exception as e:
            self.logger.error(f"iwlist parse hatası: {e}")
        
        return networks
    
    def detect_encryption(self, pkt) -> str:
        """Şifreleme türünü tespit et"""
        try:
            if pkt.haslayer(Dot11Elt):
                for elt in pkt[Dot11Elt]:
                    if elt.ID == 48:  # RSN Information
                        return "WPA2/WPA3"
                    elif elt.ID == 221:  # Vendor Specific
                        if b'WPA' in elt.info:
                            return "WPA"
            
            return "Unknown"
            
        except Exception:
            return "Unknown"
    
    def detect_wps(self, pkt) -> bool:
        """WPS desteğini tespit et"""
        try:
            if pkt.haslayer(Dot11Elt):
                for elt in pkt[Dot11Elt]:
                    if elt.ID == 221:  # Vendor Specific
                        if b'WPS' in elt.info:
                            return True
            
            return False
            
        except Exception:
            return False
    
    def calculate_security_score(self, network: Dict) -> float:
        """Ağın güvenlik skorunu hesapla"""
        score = 10.0  # Başlangıç skoru
        
        # Şifreleme türü
        encryption = network.get('encryption', '').lower()
        if 'wep' in encryption:
            score -= 8  # WEP çok zayıf
        elif 'wpa' in encryption and 'wpa2' not in encryption:
            score -= 4  # WPA zayıf
        elif 'wpa2' in encryption:
            score -= 1  # WPA2 güçlü
        elif 'wpa3' in encryption:
            score -= 0.5  # WPA3 çok güçlü
        elif 'open' in encryption:
            score -= 10  # Açık ağ
        
        # WPS
        if network.get('wps_enabled', False):
            score -= 2  # WPS zafiyeti
        
        # SSID gizleme
        if network.get('ssid') == '<hidden>':
            score += 1  # Gizli SSID biraz daha güvenli
        
        return max(0.0, score)
    
    def remove_duplicates(self, networks: List[Dict]) -> List[Dict]:
        """Tekrarlanan ağları kaldır"""
        seen_bssids = set()
        unique_networks = []
        
        for network in networks:
            bssid = network.get('bssid')
            if bssid and bssid not in seen_bssids:
                seen_bssids.add(bssid)
                unique_networks.append(network)
        
        return unique_networks
    
    def display_networks(self, networks: List[Dict]) -> None:
        """Ağları tablo halinde göster"""
        if not networks:
            return
        
        headers = ["SSID", "BSSID", "Kanal", "Şifreleme", "WPS", "Güvenlik"]
        rows = []
        
        for network in networks[:10]:  # İlk 10 ağı göster
            rows.append([
                network.get('ssid', 'Unknown')[:20],
                network.get('bssid', 'Unknown')[:17],
                str(network.get('channel', 'Unknown')),
                network.get('encryption', 'Unknown'),
                "Evet" if network.get('wps_enabled') else "Hayır",
                f"{network.get('security_score', 0):.1f}/10"
            ])
        
        self.logger.table(headers, rows, "Bulunan Wi-Fi Ağları")
    
    def check_monitor_mode(self, interface: str = "wlan0") -> bool:
        """Monitor mode kontrolü"""
        try:
            result = subprocess.run(
                ["iwconfig", interface],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            return "Mode:Monitor" in result.stdout
            
        except Exception:
            return False
    
    def enable_monitor_mode(self, interface: str = "wlan0") -> bool:
        """Monitor mode'u etkinleştir"""
        try:
            self.logger.info(f"Monitor mode etkinleştiriliyor: {interface}")
            
            # Arayüzü kapat
            subprocess.run(["ifconfig", interface, "down"], check=True)
            
            # Monitor mode'a geç
            subprocess.run(["iwconfig", interface, "mode", "monitor"], check=True)
            
            # Arayüzü aç
            subprocess.run(["ifconfig", interface, "up"], check=True)
            
            self.logger.success(f"Monitor mode etkinleştirildi: {interface}")
            return True
            
        except Exception as e:
            self.logger.error(f"Monitor mode etkinleştirme hatası: {e}")
            return False
    
    def cleanup(self) -> None:
        """Temizlik işlemleri"""
        # Monitor mode'u kapat (isteğe bağlı)
        pass 