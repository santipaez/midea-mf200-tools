#!/usr/bin/env python3
"""
02_port_scan.py -- Escaneo de puertos en el lavarropas Midea
============================================================
Objetivo: Detectar puertos abiertos en la IP configurada (midea_db_0167)
Metodo:   TCP connect scan (no agresivo, timeout corto)
Riesgo:   NINGUNO -- equivale a intentar conectarse normalmente
"""

import socket
import json
import sys
import os
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from midea_config import DEVICE_IP

if sys.platform == "win32":
    os.environ["PYTHONIOENCODING"] = "utf-8"
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Target confirmado desde el router
MIDEA_IP = DEVICE_IP()
MIDEA_MAC = "A4:2A:26:F5:E5:D7"
MIDEA_NAME = "midea_db_0167"

# Puertos a escanear (ampliado para no perder nada)
PORTS_TCP = {
    22: "SSH",
    23: "Telnet (debug)",
    80: "HTTP (web panel)",
    443: "HTTPS",
    554: "RTSP",
    1883: "MQTT (sin TLS)",
    2000: "Cisco SCCP / IoT",
    4443: "Midea alternativo",
    5353: "mDNS (TCP)",
    6444: "Midea M-Smart V3 (TCP) <<<",
    6445: "Midea M-Smart V3 alt",
    7000: "IoT generico",
    7547: "TR-069 (CWMP)",
    8080: "HTTP alternativo",
    8443: "HTTPS alternativo",
    8883: "MQTT (TLS)",
    8888: "IoT generico",
    9090: "IoT generico",
    10000: "Midea alternativo",
    23456: "IoT debug",
    49152: "UPnP",
    54321: "IoT generico",
}


def scan_port_tcp(ip, port, timeout=2):
    """Intenta conexion TCP a un puerto."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0
    except Exception:
        return False


def grab_banner(ip, port, timeout=3):
    """Intenta obtener un banner del servicio."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))

        if port in (80, 8080, 443, 8443):
            s.send(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        # Para otros puertos, intentar recibir banner espontaneo
        # y si no, enviar un byte null
        else:
            try:
                s.settimeout(1)
                banner = s.recv(256)
                if banner:
                    s.close()
                    return banner.hex(), banner.decode("utf-8", errors="replace")
            except socket.timeout:
                pass

            # Enviar probe minimo
            s.send(b"\x00")

        response = s.recv(1024)
        s.close()

        hex_resp = response.hex()
        text_resp = response.decode("utf-8", errors="replace").strip()
        return hex_resp, text_resp[:200] if text_resp else None
    except Exception:
        return None, None


def check_midea_protocol(ip, port=6444, timeout=3):
    """
    Probe del protocolo Midea V3.
    Envia bytes minimos para verificar si responde como Midea.
    SOLO LECTURA.
    """
    results = {}

    # Test 1: Conexion TCP pura — ver si envia banner espontaneo
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))

        # Muchos dispositivos Midea envian un banner al conectar
        try:
            s.settimeout(2)
            initial_data = s.recv(512)
            if initial_data:
                results["initial_banner"] = initial_data.hex()
                results["initial_banner_length"] = len(initial_data)

                # Verificar magic bytes
                if initial_data[:2] == b'\x5a\x5a':
                    results["protocol"] = "Midea V3 (5A5A)"
                    results["is_midea"] = True
                elif initial_data[:2] == b'\x83\x70':
                    results["protocol"] = "Midea V3 (8370)"
                    results["is_midea"] = True
                else:
                    results["protocol"] = f"Unknown (magic: {initial_data[:2].hex()})"
                    results["is_midea"] = False
        except socket.timeout:
            results["initial_banner"] = None
            results["note"] = "No spontaneous banner - device waits for client"

        # Test 2: Enviar handshake 8370 (protocolo V3 moderno)
        # Este es el formato que usa midea-local para conectar
        # 8370 = magic, seguido de tamanio y handshake request
        handshake_8370 = bytes([
            0x83, 0x70,  # Magic V3
            0x00, 0x06,  # Length
            0x20, 0x00,  # Handshake request type
            0x00, 0x00,  # Reserved
        ])

        s.send(handshake_8370)
        try:
            s.settimeout(3)
            response = s.recv(512)
            if response:
                results["handshake_response"] = response.hex()
                results["handshake_response_length"] = len(response)
                if response[:2] == b'\x83\x70':
                    results["protocol_v3_confirmed"] = True
                    results["is_midea"] = True
                    results["protocol"] = "Midea V3 (8370 handshake OK)"
        except socket.timeout:
            results["handshake_response"] = "timeout"

        s.close()

    except ConnectionRefusedError:
        results["error"] = "Connection refused"
    except socket.timeout:
        results["error"] = "Connection timeout"
    except Exception as e:
        results["error"] = str(e)

    return results


def main():
    print("=" * 72)
    print("  MIDEA MF200 REVERSE ENGINEERING -- Fase 1: Escaneo de Puertos")
    print("=" * 72)
    print(f"  Fecha:      {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Target IP:  {MIDEA_IP}")
    print(f"  Target MAC: {MIDEA_MAC}")
    print(f"  Hostname:   {MIDEA_NAME}")
    print(f"  Puertos:    {len(PORTS_TCP)} puertos TCP")

    # Verificar que el host esta vivo
    print(f"\n[PASO 1] Verificando conectividad con {MIDEA_IP}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        # Probar puerto 6444 directamente como test de vida
        result = s.connect_ex((MIDEA_IP, 6444))
        s.close()
        if result == 0:
            print(f"  [OK] Puerto 6444 responde -- dispositivo accesible")
        else:
            print(f"  [--] Puerto 6444 no responde, pero continuando scan completo...")
    except Exception as e:
        print(f"  [!!] Error de conectividad: {e}")

    # Escaneo de puertos
    print(f"\n[PASO 2] Escaneando {len(PORTS_TCP)} puertos TCP...")
    open_ports = {}

    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {
            executor.submit(scan_port_tcp, MIDEA_IP, port): (port, desc)
            for port, desc in PORTS_TCP.items()
        }

        for future in as_completed(futures):
            port, desc = futures[future]
            try:
                if future.result():
                    open_ports[port] = {"port": port, "service": desc, "state": "open"}
            except Exception:
                pass

    # Mostrar puertos abiertos
    if open_ports:
        print(f"\n  Puertos abiertos encontrados: {len(open_ports)}")
        print(f"  +{'='*60}+")
        for port in sorted(open_ports.keys()):
            info = open_ports[port]
            print(f"  | Puerto {port:<6} | {info['service']:<46} |")
        print(f"  +{'='*60}+")
    else:
        print(f"\n  [!!] Ningun puerto abierto de los {len(PORTS_TCP)} probados")
        print(f"       Verificar que el dispositivo esta encendido y conectado.")

    # Banner grabbing en puertos abiertos
    print(f"\n[PASO 3] Banner grabbing en puertos abiertos...")
    for port in sorted(open_ports.keys()):
        hex_banner, text_banner = grab_banner(MIDEA_IP, port)
        if hex_banner:
            open_ports[port]["banner_hex"] = hex_banner[:128]
            open_ports[port]["banner_text"] = text_banner
            print(f"  Puerto {port}:")
            print(f"    HEX:  {hex_banner[:80]}")
            if text_banner and text_banner.strip():
                print(f"    TEXT: {text_banner[:80]}")
        else:
            print(f"  Puerto {port}: (sin banner)")

    # Test protocolo Midea si 6444 esta abierto
    midea_check = None
    if 6444 in open_ports:
        print(f"\n[PASO 4] Probando protocolo Midea V3 en puerto 6444...")
        midea_check = check_midea_protocol(MIDEA_IP)

        if midea_check.get("is_midea"):
            print(f"  [OK] CONFIRMADO: Dispositivo habla protocolo Midea V3")
            print(f"       Protocolo: {midea_check.get('protocol', 'N/A')}")
            if midea_check.get("initial_banner"):
                print(f"       Banner inicial: {midea_check['initial_banner'][:64]}")
            if midea_check.get("handshake_response"):
                resp = midea_check["handshake_response"]
                if resp != "timeout":
                    print(f"       Handshake resp: {resp[:64]}")
        else:
            print(f"  [--] Puerto 6444 abierto pero protocolo Midea no confirmado")
            if midea_check.get("error"):
                print(f"       Error: {midea_check['error']}")
            if midea_check.get("note"):
                print(f"       Nota: {midea_check['note']}")
    else:
        print(f"\n[PASO 4] Puerto 6444 cerrado -- probando puertos alternativos Midea...")
        for alt_port in [6445, 4443, 10000]:
            if alt_port in open_ports:
                print(f"  Probando Midea V3 en puerto {alt_port}...")
                midea_check = check_midea_protocol(MIDEA_IP, port=alt_port)
                if midea_check.get("is_midea"):
                    print(f"  [OK] Midea V3 detectado en puerto {alt_port}!")
                    break

    # Resumen final
    print("\n" + "=" * 72)
    print("  RESUMEN FINAL")
    print("=" * 72)
    print(f"  Dispositivo:       {MIDEA_NAME}")
    print(f"  IP:                {MIDEA_IP}")
    print(f"  MAC:               {MIDEA_MAC}")
    print(f"  Puertos abiertos:  {', '.join(str(p) for p in sorted(open_ports.keys())) if open_ports else 'ninguno'}")
    print(f"  Protocolo Midea:   {'CONFIRMADO' if midea_check and midea_check.get('is_midea') else 'NO CONFIRMADO'}")

    # Guardar resultados
    output_file = Path(__file__).parent / "results" / "02_port_scan.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)

    output_data = {
        "timestamp": datetime.now().isoformat(),
        "target": {
            "ip": MIDEA_IP,
            "mac": MIDEA_MAC,
            "name": MIDEA_NAME,
            "device_type": "0xDB (Front Load Washer)",
        },
        "ports_scanned": list(PORTS_TCP.keys()),
        "open_ports": {str(k): v for k, v in open_ports.items()},
        "midea_protocol_check": midea_check,
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)

    print(f"\n  [>] Resultados guardados en: {output_file}")
    print("=" * 72)


if __name__ == "__main__":
    main()
