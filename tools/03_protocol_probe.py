#!/usr/bin/env python3
"""
03_protocol_probe.py — Pruebas de protocolo de red
===================================================
Objetivo: Detectar si el dispositivo responde a protocolos de discovery
Método:   Envía broadcast/multicast de discovery estándar
Riesgo:   NINGUNO — estos son paquetes de discovery estándar

Protocolos probados:
  - Midea V3 UDP Discovery (broadcast a puerto 6445)
  - mDNS (multicast 224.0.0.251:5353)
  - SSDP/UPnP (multicast 239.255.255.250:1900)
"""

import socket
import struct
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from midea_config import BROADCAST_IP


def midea_udp_discovery(timeout=5):
    """
    Envía broadcast de discovery del protocolo Midea V3.

    El protocolo usa UDP broadcast al puerto 6445.
    El paquete de discovery es un mensaje estándar que los dispositivos
    Midea responden con su información (device_id, type, etc.)

    SOLO LECTURA — no modifica el estado del dispositivo.
    """
    print("\n[PROTOCOLO 1] Midea V3 UDP Discovery (broadcast :6445)")
    print("  Enviando broadcast de discovery...")

    # Midea discovery packet — este es el formato estándar
    # documentado en midea-local y midea-msmart
    discovery_msg = bytearray([
        0x5A, 0x5A,  # Header magic
        0x01, 0x11,  # Length / Version
        0x48, 0x00,  # Data length
        0x92, 0x00,  # ??
        0x00, 0x00, 0x00, 0x00,  # Reserved
        0x00, 0x00, 0x00, 0x00,  # Reserved
        0x00, 0x00, 0x00, 0x00,  # Reserved
        0x00, 0x00, 0x00, 0x00,  # Reserved
        0x00, 0x00, 0x00, 0x00,  # Reserved
        0x00, 0x00, 0x00, 0x00,  # Reserved
        0x00, 0x00, 0x00, 0x00,  # Reserved
        0x00, 0x00, 0x00, 0x00,  # Reserved
    ])

    # Alternativa más simple: algunos dispositivos responden a este
    # formato corto de discovery
    discovery_short = bytes.fromhex(
        "5a5a01114800920000000000000000000000000000000000"
        "000000000000000000000000000000007f75bd6b3f148587"
    )

    devices_found = []

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(timeout)
        sock.bind(("", 0))

        # Enviar broadcast
        sock.sendto(discovery_msg, ("255.255.255.255", 6445))
        sock.sendto(discovery_short, ("255.255.255.255", 6445))

        # También enviar a la subred específica
        sock.sendto(discovery_msg, (BROADCAST_IP(), 6445))
        sock.sendto(discovery_short, (BROADCAST_IP(), 6445))

        print(f"  Esperando respuestas ({timeout}s)...")

        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                data, addr = sock.recvfrom(4096)
                ip = addr[0]
                port = addr[1]

                device_info = {
                    "ip": ip,
                    "port": port,
                    "response_length": len(data),
                    "response_hex": data.hex()[:128],
                    "magic_bytes": data[:2].hex() if len(data) >= 2 else "N/A",
                }

                # Intentar parsear la respuesta Midea
                if len(data) >= 20 and data[:2] == b'\x5a\x5a':
                    device_info["protocol"] = "Midea V3"
                    device_info["is_midea"] = True

                    # Intentar extraer device_id y type del paquete
                    # La estructura varía pero generalmente:
                    # Bytes 20-27: device_id (8 bytes, little-endian)
                    if len(data) >= 28:
                        device_id_bytes = data[20:28]
                        device_id = int.from_bytes(device_id_bytes, "little")
                        device_info["device_id"] = device_id

                    # Buscar device type en la respuesta
                    # Byte 34 o byte 36 suele contener el tipo
                    if len(data) >= 35:
                        possible_type = data[34]
                        device_info["possible_device_type"] = f"0x{possible_type:02X}"
                        if possible_type == 0xDB:
                            device_info["device_type_name"] = "Front Load Washer ⭐"
                        elif possible_type == 0xDA:
                            device_info["device_type_name"] = "Top Load Washer"
                        elif possible_type == 0xDC:
                            device_info["device_type_name"] = "Dryer"
                        elif possible_type == 0xAC:
                            device_info["device_type_name"] = "Air Conditioner"

                elif len(data) >= 4 and data[:2] == b'\x83\x70':
                    device_info["protocol"] = "Midea V3 (8370)"
                    device_info["is_midea"] = True
                else:
                    device_info["protocol"] = "Unknown"
                    device_info["is_midea"] = False

                devices_found.append(device_info)
                print(f"  ✅ Respuesta de {ip}:{port}")
                print(f"     Protocolo: {device_info.get('protocol', 'N/A')}")
                if device_info.get("device_type_name"):
                    print(f"     Tipo: {device_info['device_type_name']}")
                if device_info.get("device_id"):
                    print(f"     Device ID: {device_info['device_id']}")

            except socket.timeout:
                break

        sock.close()

    except Exception as e:
        print(f"  ERROR: {e}")

    if not devices_found:
        print("  ❌ No se recibieron respuestas al discovery Midea V3")

    return devices_found


def ssdp_discovery(timeout=5):
    """
    Envía M-SEARCH SSDP/UPnP para descubrir dispositivos.
    Método estándar de discovery — todos los dispositivos UPnP responden.
    """
    print("\n[PROTOCOLO 2] SSDP/UPnP Discovery (multicast 239.255.255.250:1900)")

    SSDP_ADDR = "239.255.255.250"
    SSDP_PORT = 1900

    ssdp_request = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 3\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    ).encode()

    devices_found = []

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

        sock.sendto(ssdp_request, (SSDP_ADDR, SSDP_PORT))
        print(f"  Esperando respuestas ({timeout}s)...")

        start_time = time.time()
        seen_ips = set()

        while time.time() - start_time < timeout:
            try:
                data, addr = sock.recvfrom(4096)
                ip = addr[0]

                if ip in seen_ips:
                    continue
                seen_ips.add(ip)

                response_text = data.decode("utf-8", errors="replace")

                # Extraer información útil
                device_info = {
                    "ip": ip,
                    "port": addr[1],
                    "protocol": "SSDP/UPnP",
                }

                for line in response_text.splitlines():
                    line_lower = line.lower()
                    if line_lower.startswith("server:"):
                        device_info["server"] = line.split(":", 1)[1].strip()
                    elif line_lower.startswith("location:"):
                        device_info["location"] = line.split(":", 1)[1].strip()
                    elif line_lower.startswith("st:") or line_lower.startswith("nt:"):
                        device_info["service_type"] = line.split(":", 1)[1].strip()
                    elif "usn:" in line_lower:
                        device_info["usn"] = line.split(":", 1)[1].strip()

                devices_found.append(device_info)
                server = device_info.get("server", "N/A")
                print(f"  ✓ {ip} — Server: {server}")

            except socket.timeout:
                break

        sock.close()

    except Exception as e:
        print(f"  ERROR: {e}")

    if not devices_found:
        print("  ❌ No se recibieron respuestas SSDP")

    return devices_found


def mdns_probe(timeout=5):
    """
    Envía query mDNS para buscar servicios IoT.
    Busca específicamente servicios Midea y genéricos IoT.
    """
    print("\n[PROTOCOLO 3] mDNS Discovery (multicast 224.0.0.251:5353)")

    MDNS_ADDR = "224.0.0.251"
    MDNS_PORT = 5353

    # Construir query mDNS para _http._tcp.local y otros servicios
    # Este es un DNS query estándar RFC 6762
    def build_mdns_query(name):
        """Construye un paquete DNS query simple."""
        # Header: ID=0, Flags=0, QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        header = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)

        # Question section
        question = b""
        for part in name.split("."):
            question += bytes([len(part)]) + part.encode()
        question += b"\x00"  # Root label
        question += struct.pack(">HH", 255, 1)  # QTYPE=ANY, QCLASS=IN

        return header + question

    services_to_query = [
        "_http._tcp.local",
        "_mqtt._tcp.local",
        "_midea._tcp.local",
        "_hap._tcp.local",      # HomeKit
        "_airplay._tcp.local",
        "_services._dns-sd._udp.local",
    ]

    devices_found = []

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

        for service in services_to_query:
            query = build_mdns_query(service)
            sock.sendto(query, (MDNS_ADDR, MDNS_PORT))

        print(f"  Queries enviadas: {', '.join(services_to_query)}")
        print(f"  Esperando respuestas ({timeout}s)...")

        start_time = time.time()
        seen = set()

        while time.time() - start_time < timeout:
            try:
                data, addr = sock.recvfrom(4096)
                ip = addr[0]

                key = f"{ip}:{data[:20].hex()}"
                if key in seen:
                    continue
                seen.add(key)

                device_info = {
                    "ip": ip,
                    "port": addr[1],
                    "protocol": "mDNS",
                    "response_length": len(data),
                    "response_hex_preview": data[:32].hex(),
                }

                # Intentar extraer nombres del response
                try:
                    response_text = data.decode("utf-8", errors="replace")
                    # Buscar strings legibles en la respuesta
                    readable = "".join(
                        c if c.isprintable() else "."
                        for c in response_text
                    )
                    device_info["readable_content"] = readable[:100]
                except Exception:
                    pass

                devices_found.append(device_info)
                print(f"  ✓ {ip} — mDNS response ({len(data)} bytes)")

            except socket.timeout:
                break

        sock.close()

    except Exception as e:
        print(f"  ERROR: {e}")

    if not devices_found:
        print("  ❌ No se recibieron respuestas mDNS")

    return devices_found


def main():
    print("=" * 72)
    print("  MIDEA MF200 REVERSE ENGINEERING — Fase 1: Pruebas de Protocolo")
    print("=" * 72)
    print(f"  Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  NOTA: Todos los paquetes son de discovery estándar (solo lectura)")

    results = {
        "timestamp": datetime.now().isoformat(),
        "protocols_tested": [],
    }

    # Test 1: Midea V3 Discovery
    midea_results = midea_udp_discovery(timeout=5)
    results["midea_v3_discovery"] = midea_results
    results["protocols_tested"].append("Midea V3 UDP")

    # Test 2: SSDP/UPnP
    ssdp_results = ssdp_discovery(timeout=5)
    results["ssdp_discovery"] = ssdp_results
    results["protocols_tested"].append("SSDP/UPnP")

    # Test 3: mDNS
    mdns_results = mdns_probe(timeout=5)
    results["mdns_discovery"] = mdns_results
    results["protocols_tested"].append("mDNS")

    # Resumen
    print("\n" + "=" * 72)
    print("  RESUMEN DE PRUEBAS DE PROTOCOLO")
    print("=" * 72)

    print(f"\n  Midea V3 Discovery: {len(midea_results)} dispositivo(s) encontrado(s)")
    print(f"  SSDP/UPnP:          {len(ssdp_results)} dispositivo(s) encontrado(s)")
    print(f"  mDNS:               {len(mdns_results)} dispositivo(s) encontrado(s)")

    # Identificar el lavarropas
    midea_washers = [d for d in midea_results if d.get("device_type_name", "").startswith("Front Load")]
    if midea_washers:
        print(f"\n  🎯 LAVARROPAS MIDEA DETECTADO:")
        for w in midea_washers:
            print(f"     IP:        {w['ip']}")
            print(f"     Device ID: {w.get('device_id', 'N/A')}")
            print(f"     Tipo:      {w.get('device_type_name', 'N/A')}")
    elif midea_results:
        print(f"\n  ✅ Dispositivo(s) Midea detectado(s) (tipo por confirmar):")
        for d in midea_results:
            print(f"     IP: {d['ip']} — Type: {d.get('possible_device_type', 'N/A')}")

    # Guardar resultados
    output_file = Path(__file__).parent / "results" / "03_protocol_probe.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(f"\n  📄 Resultados guardados en: {output_file}")
    print("=" * 72)

    return results


if __name__ == "__main__":
    main()
