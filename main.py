#!/usr/bin/env python3
"""
Wireless Mesh Attack Framework
Ana başlatıcı dosyası
"""

import sys
import os
import argparse
from pathlib import Path

# Proje kök dizinini Python path'ine ekle
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from core.main import WirelessMeshAttackFramework
from core.config import Config
from core.logger import Logger

def main():
    """Ana fonksiyon"""
    parser = argparse.ArgumentParser(
        description="Wireless Mesh Attack Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnekler:
  python main.py --mode scan --interface wlan0
  python main.py --mode attack --target 192.168.1.1
  python main.py --mode pivot --device modem_001
  python main.py --mode map --output attack_map.html
        """
    )
    
    parser.add_argument(
        "--mode", 
        choices=["scan", "attack", "pivot", "map", "c2"],
        default="scan",
        help="Çalışma modu"
    )
    
    parser.add_argument(
        "--interface", 
        default="wlan0",
        help="Wi-Fi arayüzü"
    )
    
    parser.add_argument(
        "--target", 
        help="Hedef IP adresi veya SSID"
    )
    
    parser.add_argument(
        "--device", 
        help="Cihaz ID'si"
    )
    
    parser.add_argument(
        "--output", 
        default="output",
        help="Çıktı dosyası"
    )
    
    parser.add_argument(
        "--config", 
        default="config/settings.json",
        help="Konfigürasyon dosyası"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Detaylı çıktı"
    )
    
    parser.add_argument(
        "--stealth", "-s",
        action="store_true",
        help="Gizlilik modu"
    )
    
    args = parser.parse_args()
    
    # Konfigürasyonu yükle
    config = Config(args.config)
    
    # Logger'ı başlat
    logger = Logger(verbose=args.verbose)
    
    try:
        # Framework'ü başlat
        framework = WirelessMeshAttackFramework(config, logger)
        
        # Moda göre çalıştır
        if args.mode == "scan":
            framework.scan_networks(args.interface)
        elif args.mode == "attack":
            framework.attack_target(args.target, args.interface)
        elif args.mode == "pivot":
            framework.pivot_from_device(args.device)
        elif args.mode == "map":
            framework.create_attack_map(args.output)
        elif args.mode == "c2":
            framework.start_c2_server()
            
    except KeyboardInterrupt:
        logger.info("Kullanıcı tarafından durduruldu")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Hata: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 