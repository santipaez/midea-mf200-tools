#!/usr/bin/env python3
"""
04_read_raw_bytes.py — Sesión de solo lectura y mapeo de bytes (Corregido)
========================================================================
Objetivo: Conectarse al lavarropas, obtener el estado actual, capturar la respuesta
          decriptada y mapear cada byte del payload a atributos conocidos/desconocidos.
          Corrige la serialización JSON y el desfase de 10 bytes del header.
"""

import sys
import os
import json
import asyncio
import argparse
from pathlib import Path
from datetime import datetime

# Importar dependencias de midea-local
import aiohttp
from midealocal.const import ProtocolVersion, DeviceType
from midealocal.discover import discover
from midealocal.cloud import get_midea_cloud
from midealocal.devices.db import MideaDBDevice, DeviceAttributes
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
OUTPUT_FILE = Path(__file__).parent / "results" / "04_raw_status.json"

captured_payload = None

class CustomMideaDBDevice(MideaDBDevice):
    """Subclase para interceptar y capturar el mensaje desencriptado."""
    def process_message(self, msg: bytes) -> dict:
        global captured_payload
        captured_payload = bytearray(msg)
        return super().process_message(msg)

async def get_credentials_from_cloud(username, password, cloud_name, device_id):
    """Autentica con la nube de Midea y obtiene las llaves criptográficas (token y key)."""
    async with aiohttp.ClientSession() as session:
        cloud = get_midea_cloud(cloud_name, session, username, password)
        print(f"[*] Intentando login en Midea Cloud ({cloud_name}) para {username}...")
        if not await cloud.login():
            print("[-] Error de autenticación en la nube.")
            sys.exit(1)
        
        print(f"[+] Login exitoso. Buscando llaves para el dispositivo ID: {device_id}...")
        cloud_keys = await cloud.get_cloud_keys(device_id)
        default_keys = await cloud.get_default_keys()
        all_keys = {**cloud_keys, **default_keys}
        
        if not all_keys:
            print("[-] No se pudieron obtener llaves para este dispositivo.")
            sys.exit(1)
            
        for key in all_keys.values():
            if key.get("token") and key.get("key"):
                return key["token"], key["key"]
                
        print("[-] No se encontró un par token/key válido en la respuesta de la nube.")
        sys.exit(1)

def print_binary(val):
    """Representación binaria amigable de 8 bits."""
    return f"{val:08b}"

def get_mapped_description(idx):
    """Devuelve la descripción del byte del frame completo (incluyendo offset de 10 bytes del header)."""
    if idx < 10:
        header_mapping = {
            0: "HEADER: Magic Byte (0xAA)",
            1: "HEADER: Longitud del mensaje (excluyendo checksum final)",
            2: "HEADER: Tipo de Dispositivo (Device Type - 0xDB para Front Load Washer)",
            3: "HEADER: Checksum del Frame (Device Type ^ Length)",
            4: "HEADER: Reservado (0x00)",
            5: "HEADER: Reservado (0x00)",
            6: "HEADER: ID de Secuencia del Frame (Frame ID)",
            7: "HEADER: Versión del Protocolo del Frame",
            8: "HEADER: Versión del Protocolo del Dispositivo",
            9: "HEADER: Tipo de Mensaje (Message Type - 0x03:Query, 0x04:Notify, 0x02:Set)",
        }
        return header_mapping.get(idx)
        
    # Mapeo del cuerpo (offset = 10)
    body_idx = idx - 10
    body_mapping = {
        0: "BODY: Tipo de cuerpo del mensaje (ListTypes - 0x03 o 0x04)",
        1: "BODY: Power (Encendido: 0x00=Apagado, 0x01=Encendido)",
        2: "BODY: Operational Status (0:idle, 1:standby, 2:start, 3:pause, 4:end, 5:fault, 6:delay)",
        3: "BODY: Mode (0:normal, 1:factory_test, 2:service, 3:normal_continus)",
        4: "BODY: Program (ID del programa activo/seleccionado)",
        5: "BODY: Water Level (Nivel de agua — 1:Low, 2:Mid, 3:High, 4:4, 5:Auto, 0xFF:default)",
        6: "BODY: NO MAPEADO (washing_data[3]) - Posible flag adicional de lavado/secado",
        7: "BODY: Temperature (Temperatura — 1:0C, 2:20C, 3:30C, 4:40C, 5:60C, 6:95C, 7:70C)",
        8: "BODY: Centrifugado Speed (0:0, 1:400, 2:600, 3:800, 4:1000, 5:1200, 6:1400, 7:1600, 8:1300)",
        9: "BODY: Wash Time (Tiempo de lavado configurable)",
        10: "BODY: Dehydration Time (Tiempo de centrifugado configurable)",
        11: "BODY: Detergent autodosis/nivel",
        12: "BODY: Softener autodosis/nivel",
        13: "BODY: NO MAPEADO (washing_data[10])",
        14: "BODY: NO MAPEADO (washing_data[11])",
        15: "BODY: NO MAPEADO (washing_data[12])",
        16: "BODY: Progress Bitmask (Fase actual — bit 0:Spin, 1:Rinse, 2:Wash, 3:Pre-wash, 4:Dry, 5:Weight, 6:Hi-speed Spin)",
        17: "BODY: Time Remaining LSB (Minutos restantes - byte bajo)",
        18: "BODY: Time Remaining MSB (Minutos restantes - byte alto)",
        19: "BODY: NO MAPEADO (Capacidades/Flags)",
        20: "BODY: NO MAPEADO (Capacidades/Flags)",
        21: "BODY: NO MAPEADO (Capacidades/Flags)",
        22: "BODY: NO MAPEADO (Capacidades/Flags)",
        23: "BODY: NO MAPEADO (Capacidades/Flags)",
        24: "BODY: NO MAPEADO (Capacidades/Flags)",
        25: "BODY: NO MAPEADO (Capacidades/Flags)",
        26: "BODY: Stains (Manchas)",
        27: "BODY: Wash Time Value (Tiempo restante real lavado)",
        28: "BODY: Dehydration Time Value (Tiempo restante real centrifugado)",
        29: "BODY: NO MAPEADO (Capacidades/Flags)",
        30: "BODY: Dirty Degree (Grado de suciedad)",
    }
    
    if body_idx in body_mapping:
        return body_mapping[body_idx]
    elif idx == len(captured_payload) - 1:
        return "FOOTER: Checksum total del mensaje"
    else:
        return f"BODY: NO MAPEADO (Byte {body_idx} del cuerpo / Byte {idx} del frame)"

def sanitize_for_json(obj):
    """Convierte bytearray y bytes a tipos serializables en JSON (hex strings)."""
    if isinstance(obj, dict):
        return {k: sanitize_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [sanitize_for_json(x) for x in obj]
    elif isinstance(obj, bytearray | bytes):
        return obj.hex()
    return obj

async def main():
    parser = argparse.ArgumentParser(description="Sesión de solo lectura del lavarropas Midea.")
    parser.add_argument("-u", "--username", help="Email de MSmartHome")
    parser.add_argument("-p", "--password", help="Password de MSmartHome")
    parser.add_argument("-cn", "--cloud-name", default="SmartHome", help="Nube (def: SmartHome)")
    args = parser.parse_args()

    print("=" * 72)
    print("  MIDEA MF200 REVERSE ENGINEERING — Fase 2: Sesión de Solo Lectura")
    print("=" * 72)

    # 1. Descubrir dispositivo localmente
    print("[*] Escaneando IP configurada...")
    devices = discover(ip_address=DEVICE_IP())
    if not devices:
        print("[-] Error: No se encontró el lavarropas en la IP configurada")
        sys.exit(1)
        
    dev_info = list(devices.values())[0]
    device_id = dev_info["device_id"]
    print(f"[+] Lavarropas encontrado localmente!")
    print(f"    ID:       {device_id}")
    print(f"    Modelo:   {dev_info['model']}")
    print(f"    Protocolo:{dev_info['protocol']}")
    
    # 2. Cargar u obtener credenciales
    token = None
    key = None
    
    if CREDENTIALS_FILE.exists():
        try:
            with open(CREDENTIALS_FILE, "r") as f:
                creds = json.load(f)
                if creds.get("device_id") == device_id:
                    token = creds.get("token")
                    key = creds.get("key")
                    print("[+] Credenciales cargadas de results/credentials.json (local)")
        except Exception as e:
            print(f"[-] Error al leer credenciales locales: {e}")
            
    if not token or not key:
        if not args.username or not args.password:
            print("[-] Error: No hay credenciales locales guardadas. Debes proveer --username y --password")
            sys.exit(1)
            
        token, key = await get_credentials_from_cloud(args.username, args.password, args.cloud_name, device_id)
        # Guardar localmente
        CREDENTIALS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(CREDENTIALS_FILE, "w") as f:
            json.dump({"device_id": device_id, "token": token, "key": key}, f, indent=2)
        print("[+] Credenciales guardadas en results/credentials.json para futuras conexiones locales.")

    # 3. Conectarse al dispositivo de forma local y consultar estado
    print("\n[*] Conectando al dispositivo e iniciando handshake local...")
    device = CustomMideaDBDevice(
        name="midea_db_0167",
        device_id=device_id,
        ip_address=DEVICE_IP(),
        port=6444,
        token=token,
        key=key,
        device_protocol=ProtocolVersion.V3,
        model=dev_info["model"],
        subtype=0,
        customize=""
    )
    
    if not device.connect():
        print("[-] Falló la conexión local al lavarropas.")
        sys.exit(1)
        
    print("[+] Conectado y autenticado localmente.")
    
    # Hacer refresh
    print("[*] Solicitando estado actual (Query)...")
    device.refresh_status(check_protocol=True)
    device.close_socket()
    
    if captured_payload is None:
        print("[-] Error: No se pudo capturar el payload desencriptado del dispositivo.")
        sys.exit(1)
        
    print(f"[+] Payload de estado desencriptado recibido ({len(captured_payload)} bytes).")
    
    # 4. Generar reporte byte-by-byte
    print("\n" + "=" * 72)
    print("  MAPEO DE BYTES DEL STATUS PAYLOAD (DESENCRIPTADO)")
    print("=" * 72)
    print(f"  {'Byte':<4} | {'HEX':<4} | {'DEC':<3} | {'BINARIO':<8} | {'Significado / Descripción':<40}")
    print("  " + "-" * 70)
    
    byte_list = []
    unmapped_bytes = {}
    
    for idx, val in enumerate(captured_payload):
        hex_str = f"0x{val:02X}"
        bin_str = print_binary(val)
        desc = get_mapped_description(idx)
        print(f"  {idx:<4} | {hex_str:<4} | {val:<3} | {bin_str:<8} | {desc}")
        
        byte_list.append({
            "index": idx,
            "hex": hex_str,
            "dec": val,
            "bin": bin_str,
            "mapped_desc": desc,
            "is_mapped": "NO MAPEADO" not in desc
        })
        
        if "NO MAPEADO" in desc:
            unmapped_bytes[idx] = {
                "hex": hex_str,
                "dec": val,
                "bin": bin_str
            }
            
    print("=" * 72)
    
    # Mostrar atributos interpretados por midea-local
    print("\n  ATRIBUTOS INTERPRETADOS POR MIDEA-LOCAL:")
    print("  " + "-" * 40)
    attrs = device.attributes
    for attr, val in sorted(attrs.items()):
        if attr == "washing_data":
            val_str = " ".join(f"{b:02X}" for b in val)
        else:
            val_str = str(val)
        print(f"  * {attr:<25}: {val_str}")
    print("=" * 72)

    # 5. Escribir reporte en JSON para auditoría posterior (sanitizado)
    report = {
        "timestamp": datetime.now().isoformat(),
        "device_id": device_id,
        "raw_payload_hex": captured_payload.hex(),
        "payload_length": len(captured_payload),
        "bytes": byte_list,
        "attributes": sanitize_for_json(attrs),
        "unmapped_bytes": unmapped_bytes
    }
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
        
    print(f"\n[+] Reporte completo guardado en: {OUTPUT_FILE}")

if __name__ == "__main__":
    asyncio.run(main())
