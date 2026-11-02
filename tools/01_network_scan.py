#!/usr/bin/env python3
"""
01_network_scan.py — Escaneo ARP de la red local
=================================================
Objetivo: Identificar TODOS los dispositivos en la red <your-subnet>/24
Metodo:   ARP table del sistema + ping sweep para descubrir nuevos hosts
Riesgo:   NINGUNO — solo lectura pasiva de la tabla ARP + pings ICMP estandar
"""

import subprocess
import re
import socket
import json
import sys
import os
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# Force UTF-8 output on Windows
if sys.platform == "win32":
    os.environ["PYTHONIOENCODING"] = "utf-8"
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# OUI database parcial — fabricantes relevantes para IoT / Midea
KNOWN_OUIS = {
    # Midea / subsidiarias
    "78:E1:03": "Midea Group (Guangdong Midea Kitchen)",
    "24:33:6C": "Midea Group",
    "C8:9B:B8": "Midea Group",
    "AC:59:7A": "Midea Group",
    "58:46:8F": "Midea Group",
    "D0:32:58": "Midea Group",
    # SmartKey WiFi modules (usados por Midea)
    "34:86:5D": "NETGEAR",
    "18:FE:34": "Espressif (ESP8266/ESP32)",
    "24:0A:C4": "Espressif (ESP32)",
    "30:AE:A4": "Espressif (ESP8266)",
    "A4:CF:12": "Espressif (ESP32-S)",
    "7C:DF:A1": "Espressif (ESP32)",
    "84:CC:A8": "Espressif (ESP32)",
    "CC:50:E3": "Espressif (ESP8266)",
    "EC:FA:BC": "Espressif (ESP8266)",
    "AC:67:B2": "Espressif (ESP32)",
    "DC:4F:22": "Espressif (ESP32-S2)",
    # Broadlink
    "78:0F:77": "Broadlink",
    "34:EA:34": "Broadlink (HangZhou)",
    "A0:43:B0": "Broadlink",
    # MediaTek
    "00:0C:E7": "MediaTek",
    "9C:A2:F4": "MediaTek",
    # Hisense
    "88:E6:28": "Hisense broadband",
    # Tuya
    "D8:1F:12": "Tuya Smart",
    "10:D5:61": "Tuya Smart",
    # Realtek
    "C8:93:46": "Realtek Semiconductor",
    "00:E0:4C": "Realtek Semiconductor",
    # Common router/device vendors
    "00:50:56": "VMware",
    "08:00:27": "VirtualBox",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "48:B0:2D": "TP-Link",
    "50:C7:BF": "TP-Link",
    "60:E3:27": "TP-Link",
    "14:EB:B6": "TP-Link",
    "98:DA:C4": "TP-Link",
    "C0:06:C3": "TP-Link",
    "F4:EC:38": "TP-Link",
    "00:1A:2B": "Ayecom Technology",
    "3C:84:6A": "TP-Link",
    "B0:A7:B9": "TP-Link",
}


def get_local_ip():
    """Obtiene la IP local de la interfaz principal."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def get_subnet(ip):
    """Devuelve el prefijo de subred /24."""
    parts = ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}"


def ping_host(ip, timeout_ms=500):
    """Ping a un host. Retorna True si responde."""
    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", str(timeout_ms), ip],
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        return "TTL=" in result.stdout or "ttl=" in result.stdout
    except Exception:
        return False


def ping_sweep(subnet, start=1, end=254, max_workers=50):
    """Ping sweep de toda la subred para poblar la tabla ARP."""
    print(f"\n[PASO 1] Ping sweep de {subnet}.{start}-{subnet}.{end}...")
    print(f"         (usando {max_workers} workers paralelos, timeout 500ms)")

    alive = []
    total = end - start + 1
    done = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for i in range(start, end + 1):
            ip = f"{subnet}.{i}"
            futures[executor.submit(ping_host, ip)] = ip

        for future in as_completed(futures):
            ip = futures[future]
            done += 1
            if done % 50 == 0 or done == total:
                print(f"         Progreso: {done}/{total}")
            try:
                if future.result():
                    alive.append(ip)
            except Exception:
                pass

    print(f"         Hosts que respondieron al ping: {len(alive)}")
    return alive


def get_arp_table():
    """Lee la tabla ARP del sistema operativo."""
    print("\n[PASO 2] Leyendo tabla ARP del sistema...")
    devices = []

    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        for line in result.stdout.splitlines():
            match = re.search(
                r"(\d+\.\d+\.\d+\.\d+)\s+([\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2})\s+(\S+)",
                line,
            )
            if match:
                ip = match.group(1)
                mac = match.group(2).replace("-", ":").upper()
                entry_type = match.group(3)

                if mac == "FF:FF:FF:FF:FF:FF":
                    continue
                if ip.endswith(".255"):
                    continue

                devices.append({
                    "ip": ip,
                    "mac": mac,
                    "type": entry_type,
                })
    except Exception as e:
        print(f"  ERROR leyendo tabla ARP: {e}")

    print(f"         Encontrados {len(devices)} dispositivos en tabla ARP")
    return devices


def lookup_oui(mac):
    """Busca el fabricante por los primeros 3 octetos de la MAC."""
    prefix = mac[:8].upper()
    return KNOWN_OUIS.get(prefix, "Desconocido")


def resolve_hostname(ip, timeout=2):
    """Intenta resolver el hostname via DNS reverso."""
    try:
        socket.setdefaulttimeout(timeout)
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.timeout, OSError):
        return None


def identify_midea_candidate(device):
    """Heuristica para identificar si un dispositivo podria ser Midea."""
    score = 0
    reasons = []

    manufacturer = device.get("manufacturer", "")

    if "Midea" in manufacturer:
        score += 100
        reasons.append("MAC registrada a Midea Group")
    if "Espressif" in manufacturer:
        score += 40
        reasons.append("Chip Espressif (ESP8266/ESP32) - comun en IoT Midea")
    if "Broadlink" in manufacturer:
        score += 30
        reasons.append("Modulo Broadlink - usado en algunos Midea")
    if "MediaTek" in manufacturer:
        score += 20
        reasons.append("Chip MediaTek - posible modulo WiFi IoT")
    if "Tuya" in manufacturer:
        score += 15
        reasons.append("Modulo Tuya - algunos Midea usan plataforma Tuya")
    if "Realtek" in manufacturer:
        score += 15
        reasons.append("Chip Realtek - posible modulo WiFi IoT")
    if manufacturer == "Desconocido":
        score += 5
        reasons.append("Fabricante no identificado - podria ser modulo WiFi embebido")

    return score, reasons


def main():
    print("=" * 72)
    print("  MIDEA MF200 REVERSE ENGINEERING -- Fase 1: Escaneo de Red")
    print("=" * 72)
    print(f"  Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    local_ip = get_local_ip()
    if not local_ip:
        print("ERROR: No se pudo determinar la IP local")
        sys.exit(1)

    print(f"  IP local: {local_ip}")
    subnet = get_subnet(local_ip)
    print(f"  Subred:   {subnet}.0/24")

    # Paso 1: Ping sweep
    alive_hosts = ping_sweep(subnet)

    # Paso 2: Leer tabla ARP
    devices = get_arp_table()

    # Filtrar solo nuestra subred
    devices = [d for d in devices if d["ip"].startswith(subnet + ".")]

    # Paso 3: Enriquecer con OUI
    print("\n[PASO 3] Identificando fabricantes por OUI (MAC address)...")
    for device in devices:
        device["manufacturer"] = lookup_oui(device["mac"])
        device["hostname"] = resolve_hostname(device["ip"])
        device["ping"] = device["ip"] in alive_hosts

    # Paso 4: Identificar candidatos Midea
    print("\n[PASO 4] Buscando candidatos Midea...")
    for device in devices:
        score, reasons = identify_midea_candidate(device)
        device["midea_score"] = score
        device["midea_reasons"] = reasons

    devices.sort(key=lambda d: d["midea_score"], reverse=True)

    # Mostrar resultados
    print("\n" + "=" * 72)
    print("  RESULTADOS DEL ESCANEO")
    print("=" * 72)

    print(f"\n  Total de dispositivos encontrados: {len(devices)}")
    print(f"  Hosts que respondieron al ping: {len(alive_hosts)}")

    print("\n  +-- TODOS LOS DISPOSITIVOS ------------------------------------+")
    print(f"  | {'Ping':<5} {'IP':<18} {'MAC':<20} {'Fabricante':<25} |")
    print(f"  +--------------------------------------------------------------+")

    for d in devices:
        mfg = d["manufacturer"][:23]
        hostname_str = d["hostname"] or ""
        ping_str = "[OK]" if d["ping"] else "[--]"
        print(f"  | {ping_str:<5} {d['ip']:<18} {d['mac']:<20} {mfg:<25} |")
        if hostname_str:
            print(f"  |       Hostname: {hostname_str:<44} |")

    print(f"  +--------------------------------------------------------------+")

    # Candidatos Midea
    candidates = [d for d in devices if d["midea_score"] > 0]

    if candidates:
        print("\n  +-- CANDIDATOS MIDEA (por probabilidad) -----------------------+")
        for d in candidates:
            print(f"  | Score: {d['midea_score']:>3}/100  IP: {d['ip']:<16} MAC: {d['mac']} |")
            for reason in d["midea_reasons"]:
                print(f"  |   * {reason:<56} |")
            print(f"  +--------------------------------------------------------------+")
    else:
        print("\n  [!] No se encontraron candidatos Midea por OUI.")
        print("      Esto puede significar que el modulo WiFi usa un chip generico.")
        print("      Se continuara con escaneo de puertos en TODOS los dispositivos.")

    # Guardar resultados
    output_file = Path(__file__).parent / "results" / "01_network_scan.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)

    results = {
        "timestamp": datetime.now().isoformat(),
        "local_ip": local_ip,
        "subnet": f"{subnet}.0/24",
        "total_devices": len(devices),
        "alive_hosts": len(alive_hosts),
        "alive_host_ips": alive_hosts,
        "devices": devices,
        "midea_candidates": [d for d in devices if d["midea_score"] > 0],
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(f"\n  [>] Resultados guardados en: {output_file}")
    print("=" * 72)

    return devices


if __name__ == "__main__":
    main()
