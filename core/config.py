"""
Konfigürasyon yönetimi
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

class Config:
    """Konfigürasyon yönetimi sınıfı"""
    
    def __init__(self, config_file: str = "config/settings.json"):
        self.config_file = Path(config_file)
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Konfigürasyon dosyasını yükle"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Konfigürasyon yüklenirken hata: {e}")
                return self._get_default_config()
        else:
            # Varsayılan konfigürasyonu oluştur
            default_config = self._get_default_config()
            self._save_config(default_config)
            return default_config
    
    def _save_config(self, config: Dict[str, Any]) -> None:
        """Konfigürasyonu kaydet"""
        try:
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Konfigürasyon kaydedilirken hata: {e}")
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Varsayılan konfigürasyon"""
        return {
            "general": {
                "debug": False,
                "verbose": False,
                "stealth_mode": True,
                "log_level": "INFO"
            },
            "network": {
                "default_interface": "wlan0",
                "monitor_mode": True,
                "scan_timeout": 30,
                "max_networks": 50
            },
            "attacks": {
                "wpa2_timeout": 300,
                "deauth_packets": 10,
                "brute_force_timeout": 600,
                "max_attempts": 1000,
                "wordlist_path": "data/wordlists/passwords.txt"
            },
            "pivoting": {
                "arp_spoofing": True,
                "dns_hijacking": True,
                "traffic_monitoring": True,
                "port_scanning": True
            },
            "mapping": {
                "coordinate_collection": True,
                "real_time_updates": True,
                "map_update_interval": 60,
                "heatmap_enabled": True
            },
            "stealth": {
                "mac_spoofing": True,
                "hostname_spoofing": True,
                "log_cleaning": True,
                "traffic_masking": True,
                "random_delays": True
            },
            "c2": {
                "server_port": 8080,
                "server_host": "0.0.0.0",
                "encryption": True,
                "authentication": True
            },
            "automation": {
                "attack_interval": 30,
                "mapping_interval": 60,
                "max_targets_per_cycle": 5,
                "auto_spread": True
            },
            "paths": {
                "captures_dir": "data/captures",
                "handshakes_dir": "data/captures/handshakes",
                "traffic_dir": "data/captures/traffic",
                "logs_dir": "data/captures/logs",
                "databases_dir": "data/databases",
                "wordlists_dir": "data/wordlists",
                "payloads_dir": "payloads"
            },
            "plugins": {
                "auto_load": True,
                "plugin_dir": "plugins",
                "enabled_plugins": [
                    "reconnaissance.wifi_scanner",
                    "reconnaissance.device_discovery",
                    "attacks.wpa2_handshake",
                    "attacks.deauth_attack",
                    "pivoting.arp_spoofing",
                    "mapping.network_mapper"
                ]
            }
        }
    
    def get(self, key: str, default: Any = None) -> Any:
        """Konfigürasyon değerini al"""
        keys = key.split('.')
        value = self.config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any) -> None:
        """Konfigürasyon değerini ayarla"""
        keys = key.split('.')
        config = self.config
        
        # Son anahtara kadar git
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        # Değeri ayarla
        config[keys[-1]] = value
        
        # Kaydet
        self._save_config(self.config)
    
    def get_section(self, section: str) -> Dict[str, Any]:
        """Konfigürasyon bölümünü al"""
        return self.config.get(section, {})
    
    def update_section(self, section: str, values: Dict[str, Any]) -> None:
        """Konfigürasyon bölümünü güncelle"""
        if section not in self.config:
            self.config[section] = {}
        
        self.config[section].update(values)
        self._save_config(self.config)
    
    def reload(self) -> None:
        """Konfigürasyonu yeniden yükle"""
        self.config = self._load_config()
    
    def export(self, output_file: str) -> None:
        """Konfigürasyonu dışa aktar"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Konfigürasyon dışa aktarılırken hata: {e}")
    
    def import_config(self, input_file: str) -> None:
        """Konfigürasyonu içe aktar"""
        try:
            with open(input_file, 'r', encoding='utf-8') as f:
                imported_config = json.load(f)
            
            # Mevcut konfigürasyonu güncelle
            self._merge_configs(self.config, imported_config)
            self._save_config(self.config)
            
        except Exception as e:
            print(f"Konfigürasyon içe aktarılırken hata: {e}")
    
    def _merge_configs(self, base: Dict[str, Any], update: Dict[str, Any]) -> None:
        """İki konfigürasyonu birleştir"""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_configs(base[key], value)
            else:
                base[key] = value
    
    def validate(self) -> bool:
        """Konfigürasyonu doğrula"""
        required_sections = ["general", "network", "attacks", "paths"]
        
        for section in required_sections:
            if section not in self.config:
                print(f"Eksik konfigürasyon bölümü: {section}")
                return False
        
        return True
    
    def get_path(self, path_key: str) -> Path:
        """Yol değerini Path objesi olarak al"""
        path_str = self.get(f"paths.{path_key}")
        if path_str:
            return Path(path_str)
        return Path()
    
    def ensure_directories(self) -> None:
        """Gerekli dizinleri oluştur"""
        path_section = self.config.get("paths", {})
        
        for key, path_str in path_section.items():
            if path_str:
                path = Path(path_str)
                path.mkdir(parents=True, exist_ok=True) 