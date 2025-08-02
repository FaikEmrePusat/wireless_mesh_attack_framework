"""
Plugin yönetim sistemi
"""

import importlib
import inspect
import os
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
from abc import ABC, abstractmethod

from .config import Config
from .logger import Logger

class BasePlugin(ABC):
    """Temel plugin sınıfı"""
    
    def __init__(self, config: Config, logger: Logger):
        self.config = config
        self.logger = logger
        self.name = self.__class__.__name__
        self.version = "1.0.0"
        self.description = "Base plugin"
    
    @abstractmethod
    def execute(self, *args, **kwargs) -> Any:
        """Ana çalıştırma metodu"""
        pass
    
    def setup(self) -> bool:
        """Plugin kurulumu"""
        return True
    
    def cleanup(self) -> None:
        """Plugin temizliği"""
        pass
    
    def get_info(self) -> Dict[str, Any]:
        """Plugin bilgilerini döndür"""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "class": self.__class__.__name__
        }

class PluginManager:
    """Plugin yönetim sistemi"""
    
    def __init__(self, config: Config, logger: Logger):
        self.config = config
        self.logger = logger
        self.plugins: Dict[str, BasePlugin] = {}
        self.plugin_dir = Path(config.get("plugins.plugin_dir", "plugins"))
        
        # Plugin dizinini Python path'ine ekle
        if self.plugin_dir.exists():
            sys.path.insert(0, str(self.plugin_dir.parent))
    
    def discover_plugins(self) -> List[str]:
        """Mevcut plugin'leri keşfet"""
        discovered_plugins = []
        
        if not self.plugin_dir.exists():
            self.logger.warning(f"Plugin dizini bulunamadı: {self.plugin_dir}")
            return discovered_plugins
        
        # Alt dizinleri tara
        for subdir in self.plugin_dir.iterdir():
            if subdir.is_dir():
                # __init__.py dosyasını kontrol et
                init_file = subdir / "__init__.py"
                if init_file.exists():
                    # Alt dizindeki Python dosyalarını tara
                    for py_file in subdir.glob("*.py"):
                        if py_file.name != "__init__.py":
                            plugin_name = f"{subdir.name}.{py_file.stem}"
                            discovered_plugins.append(plugin_name)
        
        self.logger.info(f"{len(discovered_plugins)} plugin keşfedildi")
        return discovered_plugins
    
    def load_plugin(self, plugin_name: str) -> Optional[BasePlugin]:
        """Plugin yükle"""
        # Zaten yüklenmiş mi kontrol et
        if plugin_name in self.plugins:
            return self.plugins[plugin_name]
        
        try:
            # Plugin modülünü import et
            module = importlib.import_module(f"plugins.{plugin_name}")
            
            # Plugin sınıfını bul
            plugin_class = None
            for name, obj in inspect.getmembers(module):
                if (inspect.isclass(obj) and 
                    issubclass(obj, BasePlugin) and 
                    obj != BasePlugin):
                    plugin_class = obj
                    break
            
            if not plugin_class:
                self.logger.error(f"Plugin sınıfı bulunamadı: {plugin_name}")
                return None
            
            # Plugin'i oluştur
            plugin = plugin_class(self.config, self.logger)
            
            # Kurulum yap
            if plugin.setup():
                self.plugins[plugin_name] = plugin
                self.logger.success(f"Plugin yüklendi: {plugin_name}")
                return plugin
            else:
                self.logger.error(f"Plugin kurulumu başarısız: {plugin_name}")
                return None
                
        except ImportError as e:
            self.logger.error(f"Plugin import hatası ({plugin_name}): {e}")
            return None
        except Exception as e:
            self.logger.error(f"Plugin yükleme hatası ({plugin_name}): {e}")
            return None
    
    def load_all_plugins(self) -> Dict[str, BasePlugin]:
        """Tüm plugin'leri yükle"""
        enabled_plugins = self.config.get("plugins.enabled_plugins", [])
        
        for plugin_name in enabled_plugins:
            self.load_plugin(plugin_name)
        
        self.logger.info(f"{len(self.plugins)} plugin yüklendi")
        return self.plugins
    
    def unload_plugin(self, plugin_name: str) -> bool:
        """Plugin'i kaldır"""
        if plugin_name in self.plugins:
            plugin = self.plugins[plugin_name]
            
            # Temizlik yap
            try:
                plugin.cleanup()
            except Exception as e:
                self.logger.error(f"Plugin temizlik hatası ({plugin_name}): {e}")
            
            # Plugin'i kaldır
            del self.plugins[plugin_name]
            self.logger.info(f"Plugin kaldırıldı: {plugin_name}")
            return True
        
        return False
    
    def get_plugin(self, plugin_name: str) -> Optional[BasePlugin]:
        """Plugin'i al"""
        return self.plugins.get(plugin_name)
    
    def get_loaded_plugins(self) -> List[str]:
        """Yüklenmiş plugin'lerin listesini döndür"""
        return list(self.plugins.keys())
    
    def get_plugin_info(self, plugin_name: str) -> Optional[Dict[str, Any]]:
        """Plugin bilgilerini al"""
        plugin = self.get_plugin(plugin_name)
        if plugin:
            return plugin.get_info()
        return None
    
    def execute_plugin(self, plugin_name: str, *args, **kwargs) -> Any:
        """Plugin'i çalıştır"""
        plugin = self.get_plugin(plugin_name)
        if not plugin:
            self.logger.error(f"Plugin bulunamadı: {plugin_name}")
            return None
        
        try:
            self.logger.info(f"Plugin çalıştırılıyor: {plugin_name}")
            result = plugin.execute(*args, **kwargs)
            self.logger.success(f"Plugin tamamlandı: {plugin_name}")
            return result
        except Exception as e:
            self.logger.error(f"Plugin çalıştırma hatası ({plugin_name}): {e}")
            return None
    
    def list_plugins(self) -> None:
        """Plugin listesini yazdır"""
        self.logger.section("Yüklenmiş Plugin'ler")
        
        if not self.plugins:
            self.logger.info("Hiç plugin yüklenmemiş")
            return
        
        headers = ["Plugin", "Versiyon", "Açıklama"]
        rows = []
        
        for plugin_name, plugin in self.plugins.items():
            info = plugin.get_info()
            rows.append([
                plugin_name,
                info.get("version", "Unknown"),
                info.get("description", "No description")
            ])
        
        self.logger.table(headers, rows)
    
    def reload_plugin(self, plugin_name: str) -> bool:
        """Plugin'i yeniden yükle"""
        # Önce kaldır
        self.unload_plugin(plugin_name)
        
        # Sonra yeniden yükle
        plugin = self.load_plugin(plugin_name)
        return plugin is not None
    
    def validate_plugin(self, plugin_name: str) -> bool:
        """Plugin'i doğrula"""
        try:
            # Plugin'i yükle
            plugin = self.load_plugin(plugin_name)
            if not plugin:
                return False
            
            # Temel metodları kontrol et
            if not hasattr(plugin, 'execute'):
                self.logger.error(f"Plugin execute metodu eksik: {plugin_name}")
                return False
            
            # Test çalıştırması yap
            try:
                plugin.execute()
            except Exception as e:
                self.logger.warning(f"Plugin test çalıştırması başarısız ({plugin_name}): {e}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Plugin doğrulama hatası ({plugin_name}): {e}")
            return False
    
    def cleanup_all(self) -> None:
        """Tüm plugin'leri temizle"""
        for plugin_name in list(self.plugins.keys()):
            self.unload_plugin(plugin_name)
        
        self.logger.info("Tüm plugin'ler temizlendi") 