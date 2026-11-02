#!/usr/bin/env python3
"""
07_test_raw_program.py — Herramienta Interactiva de Inyección de Programas
==========================================================================
Objetivo: Probar dinámicamente diferentes Program IDs del lavarropas Midea
          para encontrar un ciclo seco de ventilación (Air Wash, Drying, etc.)
          sin agua y con Aire Fresco activo.
Riesgo:   BAJO — comandos reversibles y no invasivos. Sin agua ni calor.
"""

import sys
import os
import json
import asyncio
from pathlib import Path

# Importar dependencias de midea-local
from midealocal.const import ProtocolVersion
from midealocal.discover import discover
from midealocal.devices.db import MideaDBDevice
from midealocal.message import MessageQuestCustom, MessageType
from midealocal.packet_builder import PacketBuilder
from midealocal.security import MSGTYPE_ENCRYPTED_REQUEST
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

# Programas candidatos del firmware para probar
PROGRAM_CANDIDATES = {
    "1": {"id": 0x15, "name": "air_wash (Lavado con Aire / Refrescar) - Incompatible?"},
    "2": {"id": 0x16, "name": "single_drying (Secado Único)"},
    "3": {"id": 0x69, "name": "fresh_remove_wrinkle (Quitar Arrugas Fresco) - Incompatible?"},
    "4": {"id": 0x82, "name": "time_dry (Secado por Tiempo)"},
    "5": {"id": 0x6D, "name": "steam_care (Cuidado de Vapor - Soporta Aire Fresco)"},
    "6": {"id": 0x03, "name": "mixed_wash (Mezcla - Soporta Aire Fresco)"},
    "7": {"id": 0x00, "name": "cotton (Algodón - Soporta Aire Fresco)"},
    "8": {"id": 0x09, "name": "single_dehydration (Centrifugado solo)"},
    "9": {"id": 0x03, "name": "mixed_wash (Mix MINIMO - 0°C, 1m, 400RPM + Aire Fresco)"},
    "A": {"id": 0x00, "name": "★ SPRAY_WASH: Cotton + spray_wash(0x04) + air_fresh, SIN tocar water_level"},
    "B": {"id": 0x3D, "name": "★ BUCKET_DRY: Secado de tambor (0x3D) — probar SIN ropa primero"},
    "C": {"id": 0x00, "name": "★ WATER_LEVEL_ZERO: Cotton + water_level=0x00 explícito + air_fresh"},
}

# Modos especiales
SPECIAL_MODES = {
    "A": "spray_wash",
    "B": "bucket_dry",
    "C": "water_zero",
}

captured_payload = None

class CustomMideaDBDevice(MideaDBDevice):
    """Subclase para interceptar respuestas y enviar comandos custom."""
    def process_message(self, msg: bytes) -> dict:
        global captured_payload
        captured_payload = bytearray(msg)
        return super().process_message(msg)

    def send_custom_set_command(self, body_payload: bytearray):
        cmd = MessageQuestCustom(
            self.device_type,
            self._message_protocol_version,
            MessageType.set,
            body_payload
        )
        data = cmd.serialize()
        msg = PacketBuilder(self.device_id, data).finalize()
        encrypted_msg = self._security.encode_8370(msg, MSGTYPE_ENCRYPTED_REQUEST)
        
        print("\n" + "=" * 72)
        print("  PREVISUALIZACIÓN DE LA TRAMA A INYECTAR (MAPEO DE 22 BYTES)")
        print("=" * 72)
        print(f"  Mensaje Desencriptado (HEX): {data.hex()}")
        
        # Mapa de nombres para los bytes del body
        body_field_names = {
            0: "control_type",
            1: "power",
            2: "start/pause",
            3: "mode",
            4: "program",
            5: "water_level",
            6: "soak|dryer",
            7: "temperature",
            8: "spin_speed",
            9: "wash_time",
            10: "spin_time",
            11: "detergent",
            12: "softener",
            13: "flags(mem|apt|spray|spd|nit|lck|dwn|iron)",
            14: "appt_time_lo",
            15: "appt_time_hi",
            16: "flags(pre|clr|smt|int|stm|fcs|soak|?)",
            17: "stains",
            18: "dirty_degree",
            19: "flags(air|bub|eye|uv|add_r|?|?|?)",
            20: "complex_key",
            21: "reserved",
        }
        
        print(f"  Mensaje Desencriptado (BIN):")
        for i, b in enumerate(data):
            if i < 10:
                print(f"  Byte {i:02d} (header): {b:02X} ({b:08b})")
            else:
                bi = i - 10
                fname = body_field_names.get(bi, "?")
                marker = ""
                if bi == 13 and (b & 0x04):
                    marker = " ← SPRAY_WASH ON"
                elif bi == 16 and (b & 0x10):
                    marker = " ← STEAM_WASH ON"
                elif bi == 19 and (b & 0x01):
                    marker = " ← AIR_FRESH ON"
                elif bi == 5 and b != 0xFF:
                    marker = f" ← WATER_LEVEL={b}"
                print(f"  Byte {i:02d} (body[{bi:02d}] {fname}): {b:02X} ({b:08b}){marker}")
        
        print("-" * 72)
        print(f"  Mensaje Cifrado Final V3 (HEX): {encrypted_msg.hex()}")
        print("=" * 72)
        
        confirm = input("\n[?] ¿Proceder con la inyección vía socket TCP? [Y/N]: ").strip().lower()
        if confirm != 'y':
            print("[-] Inyección cancelada por el usuario.")
            return False
            
        print("[*] Inyectando comando en el socket...")
        self.send_message(msg)
        return True

def construir_payload(program_id, dryer_level, activar_vapor, modo_especial=None):
    """
    Construye el payload de 22 bytes usando el mapeo oficial de control.
    
    MAPA DE BODY[13] (bit flags):
      bit 0 (0x01) = memory
      bit 1 (0x02) = appointment
      bit 2 (0x04) = spray_wash ← CLAVE para rociado fino
      bit 3 (0x08) = speedy/old_speedy
      bit 4 (0x10) = nightly
      bit 5 (0x20) = lock
      bit 6 (0x40) = down_light
      bit 7 (0x80) = easy_ironing
    """
    body = bytearray([0xFF] * 22)
    
    body[0] = 0x02  # BYTE_CONTROL_REQUEST (tipo = set)
    body[2] = 0x01  # controlWorkStatus (0x01 = start)
    
    body[4] = program_id
    body[7] = 0x01  # temperature (0x01 = 0°C / frío)
    
    if modo_especial == "spray_wash":
        # PRIORIDAD 1: spray_wash + air_fresh, SIN tocar water_level
        # body[5] queda en 0xFF (default del firmware, no tocamos el nivel de agua)
        body[8] = 0xFF  # spin speed = default
        body[9] = 0xFF  # wash time = default (firmware decide)
        body[10] = 0xFF # spin time = default
        # EXPLÍCITAMENTE activar spray_wash en body[13]
        body[13] = 0x04  # SOLO spray_wash ON (bit 2), todo lo demás OFF
        
    elif modo_especial == "bucket_dry":
        # PRIORIDAD 2: bucket_dry — no tocar agua, no tocar tiempos
        body[8] = 0xFF  # default
        body[9] = 0xFF  # default
        body[10] = 0xFF # default
        body[13] = 0x00  # todos los flags opcionales OFF
        
    elif modo_especial == "water_zero":
        # PRIORIDAD 3: cotton con water_level=0x00 explícito
        body[5] = 0x00  # waterLevel = 0 (¿error o sin agua?)
        body[8] = 0x01  # dehydrationSpeed = 400 RPM mínimo
        body[9] = 0x01  # washTime = 1 minuto
        body[10] = 0x00 # dehydrationMin = 0
        body[13] = 0x00  # flags opcionales OFF
        
    elif modo_especial == "mix_minimo":
        body[8] = 0x01  # dehydrationSpeed (0x01 = 400 RPM)
        body[9] = 0x01  # washTime (1 minuto de lavado)
        body[10] = 0x01 # dehydrationMin (1 minuto de centrifugado)
    else:
        body[8] = 0x00  # dehydrationSpeed (0x00 = 0 RPM)
        body[9] = 0x00  # washTime (0 min)
        body[10] = 0x00 # dehydrationMin (0 min / default)

    # Configuración de nivel de secado en body[6]
    soak_count = 0x0F
    body[6] = soak_count & dryer_level

    # Flag de Vapor (steam_wash) en body[16] (bit 4: 0x10)
    if activar_vapor:
        body[16] = 0x10
    else:
        body[16] = 0x00

    # Flag de Aire Fresco (wind_dispel) en body[19] (bit 0: 0x01)
    body[19] = 0x01

    return body

async def main():
    print("=" * 72)
    print("  MIDEA MF200 REVERSE ENGINEERING — Herramienta de Inyección v3")
    print("=" * 72)
    
    # 1. Cargar credenciales
    if not CREDENTIALS_FILE.exists():
        print("[-] Error: No se encontró results/credentials.json. Ejecutá primero 04_read_raw_bytes.py")
        sys.exit(1)
        
    with open(CREDENTIALS_FILE, "r") as f:
        creds = json.load(f)
        device_id = creds["device_id"]
        token = creds["token"]
        key = creds["key"]
        
    # 2. Descubrir dispositivo
    devices = discover(ip_address=DEVICE_IP())
    if not devices:
        print("[-] Error: No se encontró el lavarropas en la red local.")
        sys.exit(1)
    dev_info = list(devices.values())[0]

    # 3. Menú de Selección de Programas
    print("\n" + "-" * 72)
    print("  TESTS PRIORITARIOS (recomendados por análisis de spec):")
    print("-" * 72)
    for k in ["A", "B", "C"]:
        print(f"  [{k}] {PROGRAM_CANDIDATES[k]['name']} (ID: 0x{PROGRAM_CANDIDATES[k]['id']:02X})")
    print()
    print("  TESTS ANTERIORES:")
    for k in sorted(k for k in PROGRAM_CANDIDATES if k not in ["A", "B", "C"]):
        print(f"  [{k}] {PROGRAM_CANDIDATES[k]['name']} (ID: 0x{PROGRAM_CANDIDATES[k]['id']:02X})")
    print("  [H] Especificar un ID de programa en Hexadecimal a mano")
    print("  [Q] Salir")
    
    # FIX: normalizar input a uppercase para evitar bug de case-sensitivity
    opt = input("\n[?] Opción elegida: ").strip().upper()
    
    modo_especial = None
    if opt == 'Q':
        sys.exit(0)
    elif opt == 'H':
        hex_input = input("[?] Ingresá el ID del programa en Hex (ej: 15 o 6D): ").strip()
        try:
            program_id = int(hex_input, 16)
            program_name = f"Custom Hex 0x{program_id:02X}"
        except ValueError:
            print("[-] Formato inválido.")
            sys.exit(1)
    elif opt in PROGRAM_CANDIDATES:
        program_id = PROGRAM_CANDIDATES[opt]["id"]
        program_name = PROGRAM_CANDIDATES[opt]["name"]
        if opt in SPECIAL_MODES:
            modo_especial = SPECIAL_MODES[opt]
        elif opt == "9":
            modo_especial = "mix_minimo"
    else:
        print("[-] Opción inválida.")
        sys.exit(1)

    # 4. Configurar nivel de secado
    dryer_level = 0xF0  # Por defecto '0' (apagado)
    if program_id in [0x16, 0x82] and modo_especial is None:
        print("\nConfiguración de tiempo de secado:")
        print("  [0] Apagado / 0 minutos (0xF0)")
        print("  [1] Nivel 1 / Secado suave (0xF1)")
        print("  [2] Nivel 2 / Secado normal (0xF2)")
        print("  [3] Nivel 3 / Secado extra (0xF3)")
        dry_opt = input("[?] Elegir nivel de secado: ").strip()
        if dry_opt == "1":
            dryer_level = 0xF1
        elif dry_opt == "2":
            dryer_level = 0xF2
        elif dry_opt == "3":
            dryer_level = 0xF3
        else:
            dryer_level = 0xF0

    # Configurar vapor
    if modo_especial in ["spray_wash"]:
        # Para spray_wash NO activamos vapor (aislar la variable)
        activar_vapor = False
        print("[*] Vapor desactivado (aislando variable spray_wash)")
    elif modo_especial in ["bucket_dry", "water_zero"]:
        activar_vapor = False
        print("[*] Vapor desactivado para este test")
    else:
        vapor_opt = input("[?] ¿Activar vapor (Steam Wash)? [y/N]: ").strip().lower()
        activar_vapor = (vapor_opt == 'y')

    # 5. Conectarse
    print(f"\n[*] Conectando al lavarropas para ejecutar '{program_name}'...")
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
        
    print("[+] Conectado y autenticado.")

    # Encender equipo si está apagado
    device.refresh_status(check_protocol=True)
    if not device.get_attribute("power"):
        print("[!] El lavarropas está APAGADO. Encendiéndolo...")
        device.set_attribute("power", True)
        await asyncio.sleep(2.0)
        device.refresh_status(check_protocol=True)

    # Construir payload e inyectar
    body = construir_payload(program_id, dryer_level, activar_vapor, modo_especial)
    success = device.send_custom_set_command(body)
    
    if success:
        print("[*] Esperando respuesta del microcontrolador...")
        await asyncio.sleep(2.5)
        
        # Leer respuesta
        global captured_payload
        captured_payload = None
        device.refresh_status(check_protocol=True)
        
        if captured_payload is not None:
            status = device.get_attribute("status")
            program = device.get_attribute("program")
            power = device.get_attribute("power")
            
            print("\n" + "=" * 72)
            print("  RESPUESTA DEL DISPOSITIVO TRAS LA INYECCIÓN")
            print("=" * 72)
            print(f"  Power State   : {power}")
            print(f"  Device Status : {status} (esperado: start/running)")
            print(f"  Active Program: {program}")
            
            # Mostrar el spray_wash del estado si está disponible
            try:
                spray = device.get_attribute("spray_wash")
                print(f"  Spray Wash    : {spray}")
            except Exception:
                pass
            
            if program == "cotton" and program_id != 0x00 and modo_especial != "mix_minimo":
                print("\n  [❌ RECHAZADO] EL FIRMWARE NO SOPORTA ESTE PROGRAMA (Fallback a Algodón)")
            elif modo_especial == "bucket_dry" and program == "bucket_dry":
                print("\n  [✅ BUCKET_DRY ACEPTADO]")
                print("  VERIFICACIÓN FÍSICA (SIN ROPA):")
                print("  - ¿Gira el tambor?")
                print("  - ¿Arrancó el ventilador?")
                print("  - ¿El vidrio de la puerta se calienta? (Debe ser NO)")
                print("  - Si no calienta → ¡ENCONTRAMOS EL REFRESH!")
            elif modo_especial == "spray_wash":
                print("\n  [?] VERIFICACIÓN FÍSICA SPRAY_WASH:")
                print("  - ¿Cargó agua por la válvula principal (chorro fuerte)? → Spray no funciona")
                print("  - ¿Sale un rociado fino/niebla sin llenar el tambor? → ¡SPRAY FUNCIONA!")
                print("  - ¿Arrancó el ventilador de aire fresco?")
                print("  - ¿Gira el tambor?")
            elif modo_especial == "water_zero":
                print("\n  [?] VERIFICACIÓN FÍSICA WATER_LEVEL=0:")
                print("  - ¿Cargó agua de todos modos? → El firmware ignora 0x00")
                print("  - ¿Dio error y se detuvo? → El sensor detecta ausencia")
                print("  - ¿Arrancó sin agua? → ¡Hallazgo!")
            elif status in ["start", "running"]:
                print("\n  [✅ ACEPTADO CON ÉXITO]")
                print("  El lavarropas reporta estar ejecutando el programa.")
                print("  VERIFICACIÓN FÍSICA REQUERIDA:")
                if modo_especial == "mix_minimo":
                    print("  - ¿Arrancó el ciclo corto? Cargará poca agua fría.")
                    print("  - Al finalizar, debería quedarse ventilando en modo Aire Fresco.")
                else:
                    print("  - ¿Hay entrada de agua o jabón? (Debe ser NO)")
                    print("  - ¿Arrancó el ventilador interno?")
                    print("  - ¿Gira el tambor lentamente?")
            else:
                print(f"\n  [?] Estado retornado: {status}")
            print("=" * 72)
            
    device.close_socket()

if __name__ == "__main__":
    asyncio.run(main())
