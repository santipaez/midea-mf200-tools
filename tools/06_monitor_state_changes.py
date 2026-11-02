#!/usr/bin/env python3
"""
06_monitor_state_changes.py — Monitoreo de Cambios de Estado en Tiempo Real
==========================================================================
Objetivo: Conectarse localmente al lavarropas y monitorear la respuesta
          decriptada de forma continua, imprimiendo únicamente los bytes
          que cambian cuando el usuario interactúa con el equipo o la app.
Riesgo:   NINGUNO — solo lectura.
"""

import sys
import os
import json
import asyncio
import time
from pathlib import Path
from datetime import datetime

# Importar dependencias de midea-local
from midealocal.const import ProtocolVersion
from midealocal.discover import discover
from midealocal.devices.db import MideaDBDevice
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

captured_payload = None

class CustomMideaDBDevice(MideaDBDevice):
    """Subclase para interceptar el payload desencriptado."""
    def process_message(self, msg: bytes) -> dict:
        global captured_payload
        captured_payload = bytearray(msg)
        return super().process_message(msg)

def get_mapped_description(idx):
    """Devuelve una descripción corta para el diff."""
    if idx < 10:
        return f"HEADER Byte {idx}"
        
    body_idx = idx - 10
    body_mapping = {
        0: "BODY: Tipo de cuerpo",
        1: "BODY: Power (Encendido)",
        2: "BODY: Status (Operational State)",
        3: "BODY: Mode",
        4: "BODY: Program ID",
        5: "BODY: Water Level",
        6: "BODY: NO MAPEADO (washing_data[3])",
        7: "BODY: Temperature",
        8: "BODY: Centrifugado Speed",
        9: "BODY: Wash Time",
        10: "BODY: Dehydration Time",
        11: "BODY: Detergent level",
        12: "BODY: Softener level",
        13: "BODY: NO MAPEADO (washing_data[10])",
        14: "BODY: NO MAPEADO (washing_data[11])",
        15: "BODY: NO MAPEADO (washing_data[12])",
        16: "BODY: Progress Bitmask",
        17: "BODY: Time Remaining LSB",
        18: "BODY: Time Remaining MSB",
        26: "BODY: Stains",
        27: "BODY: Wash Time Value",
        28: "BODY: Dehydration Time Value",
        30: "BODY: Dirty Degree",
    }
    return body_mapping.get(body_idx, f"BODY: Byte {body_idx} (unmapped)")

async def main():
    print("=" * 72)
    print("  MIDEA MF200 REVERSE ENGINEERING — Monitoreo de Cambios de Estado")
    print("=" * 72)
    print("[*] Leyendo credenciales locales...")
    
    if not CREDENTIALS_FILE.exists():
        print("[-] Error: No se encontró results/credentials.json. Ejecutá primero 04_read_raw_bytes.py")
        sys.exit(1)
        
    with open(CREDENTIALS_FILE, "r") as f:
        creds = json.load(f)
        device_id = creds["device_id"]
        token = creds["token"]
        key = creds["key"]
        
    print(f"[+] Credenciales cargadas. Device ID: {device_id}")

    # Descubrir dispositivo para obtener modelo
    devices = discover(ip_address=DEVICE_IP())
    if not devices:
        print("[-] Error: No se puede encontrar el lavarropas localmente.")
        sys.exit(1)
    dev_info = list(devices.values())[0]

    # Conectarse localmente
    print("\n[*] Conectando al lavarropas y comenzando monitoreo (Ctrl+C para salir)...")
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
        print("[-] Falló la conexión local.")
        sys.exit(1)
        
    print("[+] Conectado. Monitoreando cambios...")
    
    # Obtener estado inicial
    global captured_payload
    device.refresh_status(check_protocol=True)
    
    if captured_payload is None:
        print("[-] Error: No se recibió payload inicial.")
        sys.exit(1)
        
    last_payload = bytearray(captured_payload)
    print(f"[+] Estado inicial recibido ({len(last_payload)} bytes).")
    print("[*] Probá lo siguiente en la App o en el panel físico:")
    print("    1. Cambiar de programa (Algodón, Mix, etc.)")
    print("    2. Activar/desactivar la opción 'Aire Fresco'")
    print("    3. Activar/desactivar otras opciones (Vapor, Prelavado, Centrifugado, Temp)")
    print("-" * 72)
    
    try:
        while True:
            # Enviar query cada 2 segundos
            await asyncio.sleep(2.0)
            try:
                # refresh_status enviará la query y actualizará captured_payload (con check_protocol=True para lectura síncrona)
                device.refresh_status(check_protocol=True)
                
                if captured_payload is not None and captured_payload != last_payload:
                    # Detectar diferencias
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    print(f"\n[{timestamp}] Cambio detectado:")
                    print(f"  {'Byte':<4} | {'HEX ANTERIOR':<12} | {'HEX NUEVO':<12} | {'BINARIO NUEVO':<13} | {'Significado':<30}")
                    print("  " + "-" * 80)
                    
                    # Asegurar longitud coincidente para comparar
                    max_len = max(len(last_payload), len(captured_payload))
                    for idx in range(max_len):
                        val_old = last_payload[idx] if idx < len(last_payload) else None
                        val_new = captured_payload[idx] if idx < len(captured_payload) else None
                        
                        if val_old != val_new:
                            old_hex = f"0x{val_old:02X} ({val_old})" if val_old is not None else "N/A"
                            new_hex = f"0x{val_new:02X} ({val_new})" if val_new is not None else "N/A"
                            new_bin = f"{val_new:08b}" if val_new is not None else "N/A"
                            desc = get_mapped_description(idx)
                            print(f"  {idx:<4} | {old_hex:<12} | {new_hex:<12} | {new_bin:<13} | {desc}")
                            
                    last_payload = bytearray(captured_payload)
                    print("-" * 80)
            except Exception as e:
                # Ignorar desconexiones temporales y reintentar
                pass
                
    except KeyboardInterrupt:
        print("\n[*] Monitoreo finalizado por el usuario.")
    finally:
        device.close_socket()

if __name__ == "__main__":
    asyncio.run(main())
