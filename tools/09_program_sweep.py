#!/usr/bin/env python3
"""
09_program_sweep.py — Barrido Silencioso de Program IDs (0x00 - 0xFF)
======================================================================
Objetivo: Encontrar qué IDs de programa acepta realmente el firmware
          de forma SILENCIOSA (en modo Standby) a nivel de socket puro,
          evitando bugs de blacklist/timeouts de la librería.

Riesgo: CERO. Sin ruidos, sin agua, sin desgaste de relés.
"""

import sys
import os
import json
import socket
import time
import asyncio
from pathlib import Path

# Importar dependencias de midea-local
from midealocal.discover import discover
from midealocal.security import LocalSecurity, MSGTYPE_ENCRYPTED_REQUEST
from midealocal.packet_builder import PacketBuilder
from midea_config import DEVICE_IP

# Forzar codificación UTF-8 en Windows
if sys.platform == "win32":
    os.environ["PYTHONIOENCODING"] = "utf-8"
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

CREDENTIALS_FILE = Path(__file__).parent / "results" / "credentials.json"
REPORT_FILE = Path(__file__).parent / "results" / "supported_programs.json"

# Nombres conocidos para reporte
KNOWN_PROGRAMS = {
    0x00: "cotton (Algodón)",
    0x01: "eco",
    0x02: "quick_wash (Rápido)",
    0x03: "mixed_wash (Mix)",
    0x04: "wool (Lana)",
    0x05: "synthetic (Sintético)",
    0x08: "rinse_spin (Enjuague y Centrifugado)",
    0x09: "single_dehydration (Centrifugado)",
    0x15: "air_wash (Lavado con Aire / Refresh)",
    0x16: "single_drying (Secado Único)",
    0x3C: "fresh_air (Aire Fresco nativo)",
    0x3D: "bucket_dry (Secado de tambor)",
    0x64: "baby_care",
    0x67: "jeans",
    0x69: "fresh_remove_wrinkle",
    0x6A: "outdoor / activewear",
    0x6B: "down_jacket",
    0x6D: "steam_care (Vapor)",
    0x82: "time_dry (Secado por Tiempo)",
}

def build_set_command(device_id, program_id, security):
    """Construye un frame de control de 22 bytes en Standby."""
    body = bytearray([0xFF] * 22)
    body[0] = 0x02  # set command
    body[2] = 0xFF  # Standby / no iniciar ciclo
    body[4] = program_id
    
    # Payload real del comando
    data = bytearray([
        0xAA, 22 + 10, 0xDB, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x02  # msg_type = set
    ])
    data.extend(body)
    # Checksum de los bytes del payload (excluyendo el header)
    checksum = (~sum(data[1:]) + 1) & 0xFF
    data.append(checksum)
    
    # Envolver en packet v2 y encriptar v3
    msg = PacketBuilder(device_id, bytes(data)).finalize()
    return security.encode_8370(msg, MSGTYPE_ENCRYPTED_REQUEST)

def build_query_command(device_id, security):
    """Construye la query estándar (0303)."""
    query_standard = bytearray([
        0xAA, 0x0B, 0xDB, 0xD0,
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x03
    ])
    checksum = (~sum(query_standard[1:]) + 1) & 0xFF
    query_standard.append(checksum)
    
    msg = PacketBuilder(device_id, bytes(query_standard)).finalize()
    return security.encode_8370(msg, MSGTYPE_ENCRYPTED_REQUEST)

def build_power_on_command(device_id, security):
    """Construye un comando para encender el lavarropas."""
    body = bytearray([0xFF] * 22)
    body[0] = 0x02  # set command
    body[1] = 0x01  # Power = ON
    
    data = bytearray([
        0xAA, 22 + 10, 0xDB, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x02  # msg_type = set
    ])
    data.extend(body)
    checksum = (~sum(data[1:]) + 1) & 0xFF
    data.append(checksum)
    
    msg = PacketBuilder(device_id, bytes(data)).finalize()
    return security.encode_8370(msg, MSGTYPE_ENCRYPTED_REQUEST)

async def main():
    print("=" * 72)
    print("  MIDEA MF200 — BARRIDO SILENCIOSO DE PROGRAM IDs (SOCKET DIRECTO)")
    print("=" * 72)
    
    if not CREDENTIALS_FILE.exists():
        print("[-] Error: No se encontró results/credentials.json")
        sys.exit(1)
        
    with open(CREDENTIALS_FILE, "r") as f:
        creds = json.load(f)
        device_id = creds["device_id"]
        token = creds["token"]
        key = creds["key"]
        
    # Crear e inicializar seguridad local
    security = LocalSecurity()
    
    # Conectar socket directo
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(4.0)
    
    try:
        sock.connect((DEVICE_IP(), 6444))
        print("[+] Socket TCP conectado a la IP configurada:6444")
        
        # Handshake V3
        request = security.encode_8370(bytes.fromhex(token), 0)
        sock.send(request)
        response = sock.recv(1024)
        if not response or len(response) < 20:
            print("[-] Handshake V3 falló")
            sock.close()
            sys.exit(1)
            
        security.tcp_key(response[8:72], bytes.fromhex(key))
        print("[+] Handshake V3 completado exitosamente")
    except Exception as e:
        print(f"[-] Conexión fallida: {e}")
        sock.close()
        sys.exit(1)

    print("\n[*] Iniciando barrido sistemático de 0x00 a 0xFF...")
    print("[*] NOTA: Esto es totalmente silencioso y no arranca agua ni motores.\n")
    
    # Intentar cargar resultados anteriores para reanudar
    supported = {}
    last_tested_id = -1
    if REPORT_FILE.exists():
        try:
            with open(REPORT_FILE, "r", encoding="utf-8") as f:
                old_data = json.load(f)
                old_programs = old_data.get("supported_program_ids", {})
                for hex_str, name in old_programs.items():
                    val = int(hex_str, 16)
                    supported[val] = name
                    if val > last_tested_id:
                        last_tested_id = val
            print(f"[i] Archivo json detectado. Reanudando desde ID 0x{last_tested_id + 1:02X}...")
        except Exception as e:
            print(f"[!] No se pudo cargar results/supported_programs.json, comenzando de cero: {e}")
            supported = {0x00: KNOWN_PROGRAMS.get(0x00, "cotton")}

    start_id = last_tested_id + 1 if last_tested_id != -1 else 0x01

    for program_id in range(start_id, 256):
        # 0x00 es Cotton (fallback por defecto)
        if program_id == 0x00:
            supported[0x00] = KNOWN_PROGRAMS.get(0x00, "cotton")
            continue
            
        print(f"-> Testeando ID 0x{program_id:02X} ({KNOWN_PROGRAMS.get(program_id, 'desconocido')})... ", end="", flush=True)
        
        try:
            # 1. Enviar el cambio de programa silencioso
            set_cmd = build_set_command(device_id, program_id, security)
            sock.send(set_cmd)
            await asyncio.sleep(0.4)
            
            # Recibir posible ACK o descartarlo
            try:
                sock.recv(1024)
            except socket.timeout:
                pass
            
            # 2. Enviar query de estado
            query_cmd = build_query_command(device_id, security)
            sock.send(query_cmd)
            
            # 3. Leer respuesta de estado
            await asyncio.sleep(0.2)
            raw = sock.recv(4096)
            
            packets, incomplete = security.decode_8370(raw)
            if packets:
                for message in packets:
                    if len(message) > 56:
                        payload_type = message[2] + (message[3] << 8)
                        if payload_type not in [0x1001, 0x0001]: # Omitir acks
                            cryptographic = bytes(message[40:-16])
                            decrypted = security.aes_decrypt(cryptographic)
                            if len(decrypted) > 14:
                                reported_id = decrypted[14]
                                if reported_id == program_id:
                                    name = KNOWN_PROGRAMS.get(program_id, f"unknown_0x{program_id:02X}")
                                    print(f"¡ACEPTADO! (Reportado: 0x{reported_id:02X} - {name})")
                                    supported[program_id] = name
                                else:
                                    print("Rechazado (Fallback)")
                                    supported[program_id] = "REJECTED_FALLBACK"
                                
                                # Guardar checkpoint en tiempo real
                                report_data = {
                                    "supported_program_ids": {f"0x{k:02X}": v for k, v in supported.items() if v != "REJECTED_FALLBACK"}
                                }
                                with open(REPORT_FILE, "w", encoding="utf-8") as f:
                                    json.dump(report_data, f, indent=2, ensure_ascii=False)
                                break
                else:
                    print("Respuesta no parseable")
            else:
                print("Sin respuesta de estado")
                
        except Exception as err:
            print(f"\n[⚠️  CONEXIÓN PERDIDA] Error: {err}")
            print("======================================================================")
            print("  EL LAVARROPAS SE APAGÓ FÍSICAMENTE Y PERDIÓ LA CONEXIÓN WI-FI.")
            print("  Por favor, PRESIONÁ EL BOTÓN FÍSICO DE ENCENDIDO en el panel frontal.")
            print("  El script esperará a que el Wi-Fi se reconecte automáticamente...")
            print("======================================================================")
            
            reconnected = False
            attempt = 1
            while not reconnected:
                print(f"[*] Intento de reconexión #{attempt}...", end=" ", flush=True)
                try:
                    sock.close()
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3.0)
                    sock.connect((DEVICE_IP(), 6444))
                    request = security.encode_8370(bytes.fromhex(token), 0)
                    sock.send(request)
                    response = sock.recv(1024)
                    security.tcp_key(response[8:72], bytes.fromhex(key))
                    
                    reconnected = True
                    print("\n[+] ¡Conexión recuperada exitosamente! Continuando el barrido...\n")
                    await asyncio.sleep(1.0)
                except Exception:
                    print("falla.")
                    attempt += 1
                    await asyncio.sleep(2.0)
                
        await asyncio.sleep(0.1)

    try:
        sock.close()
    except Exception:
        pass

    # Guardar reporte final filtrando rechazados
    report_data = {
        "supported_program_ids": {f"0x{k:02X}": v for k, v in supported.items() if v != "REJECTED_FALLBACK"}
    }
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)
        
    print(f"\n[+] Resultados finales guardados en {REPORT_FILE}")
    print("=" * 72)
    print("  PROGRAMAS VÁLIDOS ENCONTRADOS EN ESTE FIRMWARE:")
    print("=" * 72)
    for k, v in sorted(report_data["supported_program_ids"].items()):
        print(f"  - {k}: {v}")
    print("=" * 72)

if __name__ == "__main__":
    asyncio.run(main())
