#!/usr/bin/env python3
"""
05_download_lua.py — Descargar Script de Protocolo Lua del Dispositivo
======================================================================
Objetivo: Conectarse a la nube Midea, obtener el Número de Serie (SN) y modelo
          específico del lavarropas, y descargar el archivo Lua de especificación
          del protocolo. Este archivo contiene la definición completa de cada byte
          y opción (como Fresh Air, Vapor, etc.) para tu modelo específico.
Riesgo:   NINGUNO — solo descarga archivos del CDN oficial de Midea.
"""

import sys
import os
import json
import asyncio
import argparse
from pathlib import Path

# Importar dependencias de midea-local
import aiohttp
from midealocal.discover import discover
from midealocal.cloud import get_midea_cloud
from midea_config import DEVICE_IP

# Forzar codificación UTF-8 en Windows
if sys.platform == "win32":
    os.environ["PYTHONIOENCODING"] = "utf-8"
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

RESULTS_DIR = Path(__file__).parent / "results"

async def main():
    parser = argparse.ArgumentParser(description="Descargar script de protocolo Lua de Midea.")
    parser.add_argument("-u", "--username", required=True, help="Email de MSmartHome")
    parser.add_argument("-p", "--password", required=True, help="Password de MSmartHome")
    parser.add_argument("-cn", "--cloud-name", default="SmartHome", help="Nube (def: SmartHome)")
    args = parser.parse_args()

    print("=" * 72)
    print("  MIDEA MF200 REVERSE ENGINEERING — Descarga de Protocolo Lua")
    print("=" * 72)

    # 1. Descubrir dispositivo localmente para obtener SN y Modelo
    print("[*] Buscando lavarropas en la red local (la IP configurada)...")
    devices = discover(ip_address=DEVICE_IP())
    if not devices:
        print("[-] Error: No se encontró el lavarropas en la IP configurada")
        sys.exit(1)
        
    dev_info = list(devices.values())[0]
    device_type = dev_info["type"]
    device_sn = dev_info["sn"]
    model = dev_info["model"]
    
    print(f"[+] Lavarropas encontrado localmente:")
    print(f"    SN:       {device_sn}")
    print(f"    Modelo:   {model}")
    print(f"    Tipo Hex: 0x{device_type:02X}")

    # 2. Conectar a la nube de Midea
    async with aiohttp.ClientSession() as session:
        cloud = get_midea_cloud(args.cloud_name, session, args.username, args.password)
        print(f"\n[*] Intentando login en Midea Cloud ({args.cloud_name})...")
        if not await cloud.login():
            print("[-] Error de autenticación en la nube.")
            sys.exit(1)
            
        print("[+] Login exitoso.")
        
        # 3. Descargar archivo Lua
        print(f"\n[*] Solicitando archivo de protocolo Lua para modelo {model} y SN...")
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        
        try:
            # Descargar Lua
            lua_filename = await cloud.download_lua(str(RESULTS_DIR), device_type, device_sn, model)
            if lua_filename:
                print(f"[+] ¡LUA DESCARGADO CON ÉXITO!")
                print(f"    Ubicación: {RESULTS_DIR / lua_filename}")
            else:
                print("[-] La nube no devolvió un archivo Lua para este dispositivo.")
                
            # Descargar Plugin (.zip que contiene la app web local/H5)
            print("[*] Solicitando archivo de plugin H5...")
            plugin_filename = await cloud.download_plugin(str(RESULTS_DIR), device_type, device_sn)
            if plugin_filename:
                print(f"[+] ¡PLUGIN H5 DESCARGADO CON ÉXITO!")
                print(f"    Ubicación: {RESULTS_DIR / plugin_filename}")
                print(f"    (Este archivo .zip contiene el código Javascript de la interfaz oficial,")
                print(f"     lo que permite auditar las opciones y comandos de la app oficial).")
            else:
                print("[-] La nube no devolvió un archivo de plugin para este dispositivo.")
                
        except Exception as e:
            print(f"[-] Ocurrió un error durante la descarga: {e}")
            print("    Nota: Algunos modelos modernos de Midea usan plugins nativos y pueden no tener scripts Lua en el CDN.")
            
    print("=" * 72)

if __name__ == "__main__":
    asyncio.run(main())
