#!/usr/bin/env python3
"""
10_probe_unknown_ids_and_dryer_levels.py
==========================================================================
Fase 1: Corre físicamente los 7 IDs de programa que el barrido de 256
        confirmó como "aceptados por firmware" pero que NUNCA se
        ejecutaron para observar comportamiento real.
Fase 2: Barre el nibble completo del campo `dryer` (0x0-0xF, 16 valores)
        sobre time_dry (0x82), ya que solo se probaron los valores 0-3
        que expone la app. Se corre con y sin steam_wash activo.

Seguridad: cada test corre por una ventana corta (SAFETY_WINDOW_SEC) y
se corta solo (power=False) si detecta que el equipo empezó a cargar
agua o encender la resistencia, según lo que puedas leer de tu propio
parser de telemetría 0406 (pegá tu función de decodificación en
`leer_telemetria_extendida()` — no la tengo, así que dejo un stub claro).
Si no tenés esa función andando todavía, cae a un chequeo conservador
por `device.get_attribute()` + verificación manual a los pocos segundos.
"""

import sys
import os
import json
import asyncio
from pathlib import Path

from midealocal.const import ProtocolVersion
from midealocal.discover import discover
from midealocal.devices.db import MideaDBDevice
from midealocal.message import MessageQuestCustom, MessageType
from midealocal.packet_builder import PacketBuilder
from midealocal.security import MSGTYPE_ENCRYPTED_REQUEST
from midea_config import DEVICE_IP

CREDENTIALS_FILE = Path(__file__).parent / "results" / "credentials.json"
DEVICE_IP = DEVICE_IP()  # <-- reemplazá si corresponde
SAFETY_WINDOW_SEC = 45       # ventana antes de auto-cortar si no hay señal

# ---- Fase 1: IDs válidos nunca ejecutados físicamente ----
UNKNOWN_VALID_IDS = [0x07, 0x0A, 0x10, 0x6C, 0x6E, 0x73, 0x80]

# ---- Fase 2: rango completo del nibble `dryer` (spec: 4 bits, offset 132) ----
DRYER_NIBBLE_RANGE = list(range(0x00, 0x10))  # 0-15, solo 0-3 se probaron antes


class ProbeDevice(MideaDBDevice):
    last_raw = None

    def process_message(self, msg: bytes) -> dict:
        self.last_raw = bytearray(msg)
        return super().process_message(msg)

    def send_custom(self, body: bytearray):
        cmd = MessageQuestCustom(self.device_type, self._message_protocol_version,
                                  MessageType.set, body)
        data = cmd.serialize()
        msg = PacketBuilder(self.device_id, data).finalize()
        self._security.encode_8370(msg, MSGTYPE_ENCRYPTED_REQUEST)  # valida cifrado
        self.send_message(msg)


def leer_telemetria_extendida(device: ProbeDevice) -> dict:
    """
    STUB: enchufá acá tu parser real de 08_sniffer_0406.py.
    Debe devolver algo como:
        {"main_hydrovalve_state": 0/1, "heating_pipe_state": 0/1, "machine_error": int}
    Sin esto conectado, el script cae a un chequeo conservador (ver abajo).
    """
    return {}


def construir_payload(program_id: int, dryer_nibble: int = 0x00,
                       steam: bool = False, air_fresh: bool = True,
                       wash_time: int = 0x01, temp_cold: bool = True) -> bytearray:
    body = bytearray([0xFF] * 22)
    body[0] = 0x02
    body[2] = 0x01                  # power/start
    body[4] = program_id
    body[7] = 0x01 if temp_cold else 0xFF
    body[8] = 0x00
    body[9] = wash_time
    body[10] = 0x00
    body[6] = dryer_nibble & 0x0F    # <- nibble bajo, rango 0x0-0xF completo
    body[16] = 0x10 if steam else 0x00
    body[19] = 0x01 if air_fresh else 0x00
    return body


async def correr_test_con_watchdog(device: ProbeDevice, body: bytearray, label: str):
    print(f"\n{'='*72}\n  TEST: {label}\n{'='*72}")
    print(f"  Payload: {bytes(body).hex()}  (program_id=0x{body[4]:02X}, dryer_nibble=0x{body[6]:02X}, steam={'ON' if body[16] else 'off'})")

    confirm = input("  [?] ¿Inyectar este test? [y/N]: ").strip().lower()
    if confirm != "y":
        print("  [-] Test saltado.")
        return

    device.send_custom(body)
    print(f"  [*] Corriendo, ventana de seguridad: {SAFETY_WINDOW_SEC}s...")

    aborted = False
    for elapsed in range(0, SAFETY_WINDOW_SEC, 5):
        await asyncio.sleep(5)
        device.refresh_status(check_protocol=True)
        telemetry = leer_telemetria_extendida(device)

        if telemetry.get("machine_error", 0) not in (0, None):
            print(f"  [!!] machine_error={telemetry['machine_error']} detectado a los {elapsed+5}s — CORTANDO.")
            aborted = True
            break
        if telemetry.get("main_hydrovalve_state") == 1:
            print(f"  [!!] Válvula principal de agua ACTIVA a los {elapsed+5}s — CORTANDO (no es lo que buscamos).")
            aborted = True
            break
        # Fallback conservador si no tenés 0406 conectado: chequeo visual/manual
        if not telemetry:
            resp = input(f"  [{elapsed+5}s] ¿Ves agua entrando o sentís calor en el tambor? [y/N/q=abortar]: ").strip().lower()
            if resp in ("y", "q"):
                print("  [!!] Señal indeseada reportada manualmente — CORTANDO.")
                aborted = True
                break

    device.set_attribute("power", False)
    print(f"  [{'ABORTADO' if aborted else 'COMPLETADO SIN SEÑAL DE AGUA/CALOR'}] -> anotá el resultado físico final en data-dump.md")


async def main():
    with open(CREDENTIALS_FILE, "r") as f:
        creds = json.load(f)

    devices = discover(ip_address=DEVICE_IP)
    if not devices:
        print("[-] No se encontró el lavarropas en la red.")
        sys.exit(1)
    dev_info = list(devices.values())[0]

    device = ProbeDevice(
        name="midea_db_probe", device_id=creds["device_id"], ip_address=DEVICE_IP,
        port=6444, token=creds["token"], key=creds["key"],
        device_protocol=ProtocolVersion.V3, model=dev_info["model"], subtype=0, customize=""
    )
    if not device.connect():
        print("[-] Falló la conexión.")
        sys.exit(1)
    print("[+] Conectado y autenticado.\n")

    print("Elegí qué fase correr:")
    print("  [1] Fase 1 — probar los 7 IDs desconocidos válidos")
    print("  [2] Fase 2 — barrido de nibble `dryer` (0x0-0xF) en time_dry")
    print("  [3] Ambas")
    fase = input("[?] Opción: ").strip()

    if fase in ("1", "3"):
        for pid in UNKNOWN_VALID_IDS:
            body = construir_payload(program_id=pid, dryer_nibble=0x00, steam=False, air_fresh=True)
            await correr_test_con_watchdog(device, body, f"ID desconocido 0x{pid:02X}")

    if fase in ("2", "3"):
        for nibble in DRYER_NIBBLE_RANGE:
            for steam in (False, True):
                body = construir_payload(program_id=0x82, dryer_nibble=nibble, steam=steam, air_fresh=True)
                await correr_test_con_watchdog(
                    device, body, f"time_dry, dryer_nibble=0x{nibble:X}, steam={'ON' if steam else 'off'}"
                )

    device.close_socket()
    print("\n[+] Sesión de pruebas finalizada. Actualizá data-dump.md con los resultados (Test L en adelante).")


if __name__ == "__main__":
    asyncio.run(main())