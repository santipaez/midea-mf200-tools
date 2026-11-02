#!/usr/bin/env python3
"""
08_sniffer_0406.py — Sniffer de Telemetría Extendida (Frames 0406)
===================================================================
Corre en PARALELO con 07_test_raw_program.py.

Conecta al lavarropas, envía queries periódicas y loguea TODO lo que
llega por el socket, buscando específicamente frames con message type
0x04 / type2 0x06 que contienen estado real de componentes físicos:
  - heating_pipe_state (resistencia ON/OFF)
  - spray_valve_state  (válvula de spray)
  - main_hydrovalve_state (válvula principal de agua)
  - door_state / door_lock_state
  - drain_pump_state
  - machine_error / motor_error
  
Uso:
  1. Abrí una terminal y corré:  python 08_sniffer_0406.py
  2. En OTRA terminal corré:     python 07_test_raw_program.py
  3. El sniffer va logueando todo lo que llega en tiempo real.
  4. Ctrl+C para detener el sniffer.

Los logs se guardan en results/sniffer_0406_log.txt
"""

import sys
import os
import json
import socket
import time
from pathlib import Path
from datetime import datetime

# Forzar codificación UTF-8 en Windows
if sys.platform == "win32":
    os.environ["PYTHONIOENCODING"] = "utf-8"
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Importar dependencias de midea-local
from midealocal.const import ProtocolVersion
from midealocal.discover import discover
from midealocal.security import LocalSecurity, MSGTYPE_ENCRYPTED_REQUEST
from midea_config import DEVICE_IP

CREDENTIALS_FILE = Path(__file__).parent / "results" / "credentials.json"
LOG_FILE = Path(__file__).parent / "results" / "sniffer_0406_log.txt"

# Mapa de campos del frame 0406 (offsets en bits desde inicio del frame)
# Convertido a byte_index = offset // 8, bit_within_byte = offset % 8
FIELDS_0406 = {
    "motor_speed":          {"byte_start": 11, "bits": 16, "type": "uint16"},
    "motor_speed_setting":  {"byte_start": 13, "bits": 16, "type": "uint16"},
    "motor_temperature":    {"byte_start": 15, "bits": 8,  "type": "uint8"},
    "IPM_temperature":      {"byte_start": 16, "bits": 8,  "type": "uint8"},
    "stage_frequency":      {"byte_start": 17, "bits": 16, "type": "uint16"},
    "watertempAD":          {"byte_start": 19, "bits": 8,  "type": "uint8"},
    "dry_in":               {"byte_start": 20, "bits": 8,  "type": "uint8"},
    "dry_out":              {"byte_start": 21, "bits": 8,  "type": "uint8"},
    "dirty_test":           {"byte_start": 22, "bits": 8,  "type": "uint8"},
    "weight_load":          {"byte_start": 28, "bits": 8,  "type": "uint8"},
    "door_state":           {"byte_start": 29, "bit": 7,   "type": "bit"},
    "door_lock_state":      {"byte_start": 29, "bit": 6,   "type": "bit"},
    "softener_state":       {"byte_start": 29, "bit": 5,   "type": "bit"},
    "detergent_state":      {"byte_start": 29, "bit": 4,   "type": "bit"},
    "drain_pump_state":     {"byte_start": 29, "bit": 3,   "type": "bit"},
    "wifi_flag":            {"byte_start": 31, "bits": 8,  "type": "uint8"},
    "heating_pipe_state":   {"byte_start": 32, "bits": 8,  "type": "uint8"},
    "main_hydrovalve_state":{"byte_start": 33, "bit": 7,   "type": "bit"},
    "pre_hydrovalve_state": {"byte_start": 33, "bit": 6,   "type": "bit"},
    "spray_valve_state":    {"byte_start": 33, "bit": 5,   "type": "bit"},
    "drying_valve_state":   {"byte_start": 33, "bit": 4,   "type": "bit"},
    "hot_water_valve_state":{"byte_start": 33, "bit": 3,   "type": "bit"},
    "machine_error":        {"byte_start": 34, "bits": 8,  "type": "uint8"},
    "motor_error":          {"byte_start": 35, "bits": 8,  "type": "uint8"},
    "motor_state":          {"byte_start": 36, "bits": 8,  "type": "uint8"},
}


def decode_0406_body(body_bytes):
    """Decodifica un body de frame 0406 usando el mapa de campos."""
    result = {}
    for field_name, spec in FIELDS_0406.items():
        try:
            idx = spec["byte_start"]
            if idx >= len(body_bytes):
                result[field_name] = "N/A (fuera de rango)"
                continue
                
            if spec["type"] == "bit":
                bit_pos = spec["bit"]
                val = (body_bytes[idx] >> bit_pos) & 1
                result[field_name] = "ON" if val else "OFF"
            elif spec["type"] == "uint16":
                if idx + 1 < len(body_bytes):
                    val = body_bytes[idx] + (body_bytes[idx + 1] << 8)
                    if val == 0xFFFF:
                        val = 0  # avoidFF
                    result[field_name] = val
                else:
                    result[field_name] = "N/A"
            else:  # uint8
                result[field_name] = body_bytes[idx]
        except Exception as e:
            result[field_name] = f"ERR: {e}"
    return result


def log_and_print(log_fh, msg):
    """Imprime en consola y escribe en el archivo de log."""
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    line = f"[{ts}] {msg}"
    print(line)
    log_fh.write(line + "\n")
    log_fh.flush()


def main():
    print("=" * 72)
    print("  MIDEA MF200 — Sniffer de Telemetría Extendida (0406)")
    print("=" * 72)
    print("  Correlo en paralelo con 07_test_raw_program.py")
    print("  Ctrl+C para detener\n")
    
    # Cargar credenciales
    if not CREDENTIALS_FILE.exists():
        print("[-] Error: No se encontró results/credentials.json")
        sys.exit(1)
        
    with open(CREDENTIALS_FILE, "r") as f:
        creds = json.load(f)
        device_id = creds["device_id"]
        token = creds["token"]
        key = creds["key"]
    
    # Descubrir dispositivo
    devices = discover(ip_address=DEVICE_IP())
    if not devices:
        print("[-] Error: No se encontró el lavarropas en la red.")
        sys.exit(1)
    
    # Crear instancia de seguridad para V3
    security = LocalSecurity()
    
    # Conectar socket TCP directo
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((DEVICE_IP(), 6444))
    print("[+] Socket TCP conectado a la IP configurada:6444")
    
    # Handshake V3 (8370)
    try:
        request = security.encode_8370(
            bytes.fromhex(token),  # handshake request (token)
            0  # MSGTYPE_HANDSHAKE_REQUEST
        )
        sock.send(request)
        response = sock.recv(1024)
        
        if not response or len(response) < 20:
            print("[-] Handshake V3 falló (respuesta corta o vacía)")
            sock.close()
            sys.exit(1)
            
        # Slicing del response a [8:72] como hace midealocal.device.authenticate()
        response_sliced = response[8:72]
        success = security.tcp_key(response_sliced, bytes.fromhex(key))
        if not success:
            print("[-] Handshake V3: fallo en derivación de clave TCP")
            sock.close()
            sys.exit(1)
        
        print("[+] Handshake V3 completado")
    except Exception as e:
        print(f"[-] Error en handshake: {e}")
        sock.close()
        sys.exit(1)
    
    # Construir el query estándar (0303) y también intentar pedir 0406
    # Query estándar
    query_standard = bytearray([
        0xAA, 0x0B, 0xDB, 0xD0,
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x03
    ])
    # Calcular checksum
    checksum = (~sum(query_standard[1:]) + 1) & 0xFF
    query_standard.append(checksum)
    
    # Query 0406 — intentamos pedir explícitamente
    query_0406 = bytearray([
        0xAA, 0x0B, 0xDB, 0xD0,
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x06
    ])
    checksum_0406 = (~sum(query_0406[1:]) + 1) & 0xFF
    query_0406.append(checksum_0406)
    
    # Query 0405 (consumo de agua/energía)
    query_0405 = bytearray([
        0xAA, 0x0B, 0xDB, 0xD0,
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x05
    ])
    checksum_0405 = (~sum(query_0405[1:]) + 1) & 0xFF
    query_0405.append(checksum_0405)
    
    with open(LOG_FILE, "a", encoding="utf-8") as log_fh:
        log_and_print(log_fh, "=" * 60)
        log_and_print(log_fh, f"SESIÓN INICIADA: {datetime.now().isoformat()}")
        log_and_print(log_fh, "=" * 60)
        
        frame_count = 0
        frame_0406_count = 0
        
        try:
            while True:
                # Enviar los tres tipos de query
                for query_name, query_data in [
                    ("0303 (estándar)", query_standard),
                    ("0406 (diagnóstico)", query_0406),
                    ("0405 (consumo)", query_0405),
                ]:
                    try:
                        from midealocal.packet_builder import PacketBuilder
                        msg = PacketBuilder(device_id, bytes(query_data)).finalize()
                        encrypted = security.encode_8370(msg, MSGTYPE_ENCRYPTED_REQUEST)
                        sock.send(encrypted)
                        
                        # Esperar respuesta
                        time.sleep(0.5)
                        
                        try:
                            raw = sock.recv(4096)
                            if raw:
                                # CAPA 1: Desencriptar 8370 (transporte V3)
                                try:
                                    packets, incomplete = security.decode_8370(raw)
                                except Exception as dec_err:
                                    frame_count += 1
                                    log_and_print(log_fh, f"  Frame #{frame_count}: {len(raw)}B raw (8370 decrypt fail: {dec_err})")
                                    continue
                                
                                if not packets:
                                    continue
                                
                                for message in packets:
                                    frame_count += 1
                                    
                                    if len(message) <= 56:
                                        log_and_print(log_fh, f"  Frame #{frame_count}: {len(message)}B (envelope muy corto)")
                                        continue
                                    
                                    # CAPA 2: Extraer payload del envelope 5a5a y desencriptar AES
                                    # Estructura del envelope 5a5a:
                                    #   [0:2]   = 5a5a (header)
                                    #   [2:4]   = payload_type
                                    #   [4:6]   = packet_length (little-endian)
                                    #   [40:-16] = ciphertext AES
                                    #   [-16:]  = checksum
                                    payload_len = message[4] + (message[5] << 8) - 56
                                    payload_type = message[2] + (message[3] << 8)
                                    
                                    if payload_type in [0x1001, 0x0001]:
                                        log_and_print(log_fh, f"  Frame #{frame_count}: payload_type=0x{payload_type:04X} (control ack, skip)")
                                        continue
                                    
                                    cryptographic = bytes(message[40:-16])
                                    if payload_len <= 0 or payload_len % 16 != 0:
                                        log_and_print(log_fh, f"  Frame #{frame_count}: payload_len={payload_len} (no alineado a 16, skip)")
                                        continue
                                    
                                    try:
                                        decrypted = security.aes_decrypt(cryptographic)
                                    except Exception as aes_err:
                                        log_and_print(log_fh, f"  Frame #{frame_count}: AES decrypt fail: {aes_err}")
                                        continue
                                    
                                    if len(decrypted) < 11:
                                        log_and_print(log_fh, f"  Frame #{frame_count}: decrypted too short ({len(decrypted)}B)")
                                        continue
                                    
                                    # Ahora tenemos el mensaje real (empieza con AA)
                                    msg_type = decrypted[9]
                                    msg_type2 = decrypted[10] if len(decrypted) > 10 else 0
                                    type_str = f"{msg_type:02X}{msg_type2:02X}"
                                    
                                    log_and_print(log_fh, f"  Frame #{frame_count} [{query_name}]: type={type_str}, len={len(decrypted)}B")
                                    log_and_print(log_fh, f"    HEX: {decrypted.hex()}")
                                    
                                    # Si es un frame 0406, decodificarlo
                                    if type_str == "0406":
                                        frame_0406_count += 1
                                        body = decrypted[10:]
                                        decoded = decode_0406_body(body)
                                        
                                        log_and_print(log_fh, "")
                                        log_and_print(log_fh, "  ╔══════════════════════════════════════════════════════╗")
                                        log_and_print(log_fh, f"  ║  FRAME 0406 #{frame_0406_count} DECODIFICADO:")
                                        log_and_print(log_fh, "  ╠══════════════════════════════════════════════════════╣")
                                        for k, v in decoded.items():
                                            marker = ""
                                            if k == "heating_pipe_state" and v not in ["N/A", 0]:
                                                marker = " ⚠️  ¡RESISTENCIA ACTIVA!"
                                            elif k == "spray_valve_state" and v == "ON":
                                                marker = " ✅ ¡SPRAY ACTIVO!"
                                            elif k == "machine_error" and v not in ["N/A", 0]:
                                                marker = " ❌ ¡ERROR!"
                                            elif k == "motor_error" and v not in ["N/A", 0]:
                                                marker = " ❌ ¡ERROR MOTOR!"
                                            log_and_print(log_fh, f"  ║  {k:30s}: {str(v):10s}{marker}")
                                        log_and_print(log_fh, "  ╚══════════════════════════════════════════════════════╝")
                                        log_and_print(log_fh, "")
                                        
                                    elif type_str == "0405":
                                        log_and_print(log_fh, f"    → Frame 0405 (consumo/estado) recibido")
                                        log_and_print(log_fh, f"    HEX body: {decrypted[10:].hex()}")
                                    
                                    elif type_str == "0303" or type_str == "0203":
                                        log_and_print(log_fh, f"    → Estado estándar recibido ({type_str})")
                                    
                        except socket.timeout:
                            pass
                    
                    except Exception as e:
                        log_and_print(log_fh, f"  Error enviando query {query_name}: {e}")
                
                # Pausa entre rondas de queries
                log_and_print(log_fh, f"  --- Ronda completada. Frames totales: {frame_count}, Frames 0406: {frame_0406_count} ---")
                time.sleep(3)
                
        except KeyboardInterrupt:
            log_and_print(log_fh, "\n[*] Sniffer detenido por el usuario (Ctrl+C)")
            log_and_print(log_fh, f"[*] Resumen: {frame_count} frames capturados, {frame_0406_count} frames 0406 decodificados")
        finally:
            sock.close()
            print(f"\n[+] Log guardado en: {LOG_FILE}")


if __name__ == "__main__":
    main()
