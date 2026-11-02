> Nota: este es el registro de trabajo original, en español. Se quitaron las referencias a credenciales y las instrucciones de intervención de hardware.

# Midea MF200 Washer-Dryer — Reverse Engineering Summary

Este documento resume los objetivos, la metodología, las pruebas realizadas, los descubrimientos técnicos y los límites del firmware encontrados durante la investigación para activar el modo **Aire Fresco (Fresh Air)** de forma autónoma en el lavasecarropas **Midea MF200D120B/T-A1**.

---

## 1. Objetivo Principal
Ejecutar el ventilador interno y la rotación lenta del tambor ("Aire Fresco") como un programa independiente y continuo, sin iniciar un ciclo de lavado (sin usar agua) ni activar la resistencia de calor (aire frío), utilizando únicamente métodos locales de red (no invasivos) sobre el protocolo TCP de Midea (Puerto 6444).

---

## 2. Metodología y Entorno de Análisis
1. **Descubrimiento Local**: Escaneo ARP y de puertos. Identificación del puerto `6444/TCP` expuesto (Midea V3 Local Protocol).
2. **Sesión de Lectura (Telemetría)**: Uso de la librería `midea-local` con las claves locales del equipo, provistas por variables de entorno y nunca guardadas en el repositorio para capturar las respuestas del estado del dispositivo en tiempo real.
3. **Análisis Diferencial (Aislamiento de Bits)**: Registro de tramas de estado antes y después de interactuar con la App oficial de MSmartHome para identificar los bytes específicos de control.
4. **Ingeniería Inversa de Protocolo (Auditoría del Plugin H5/Lua)**: Descarga del script oficial Lua (`T_0000_DB_41.lua`) y del plugin Javascript (`our-spec.js`) de los servidores de Midea para verificar las definiciones de registros de lectura y escritura.
5. **Inyección de Comandos Parametrizados**: Creación del script interactivo `07_test_raw_program.py` para construir y transmitir tramas personalizadas de 22 bytes directamente al microcontrolador a través de sockets de red.

---

## 3. Descubrimientos Clave de Protocolo

### A. Flags Identificados
* **Aire Fresco (`wind_dispel`)**:
  * **Lectura**: Bit 6 de Byte 39 del frame de estado (`body[29]`). Al activarse pasa de `0x80` a `0xC0`.
  * **Escritura**: Bit 0 de Byte 29 del frame de control de 22 bytes (`body[19]`). Se activa escribiendo `0x01` en ese byte.
* **Vapor (`steam_wash`)**:
  * **Escritura**: Bit 4 de Byte 26 del frame de control de 22 bytes (`body[16]`). Se activa escribiendo `0x10`.

### B. Diferencia de Acoplamiento Read/Write
Se descubrió que los offsets de lectura (status) y escritura (set) difieren:
* Para leer el estado de las opciones extendidas se utiliza la trama de telemetría completa de ~52 bytes.
* Para escribir y activar opciones se utiliza obligatoriamente una trama compacta de **22 bytes de cuerpo** (`bodyBytes[0:21]`). Las opciones no deseadas se inicializan en `0xFF` para que el firmware las ignore.

---

## 4. Historial de Pruebas y Comportamientos Físicos

| Estrategia | Programa Probado | Configuración Inyectada | Comportamiento Físico del Equipo | Resultado |
| :--- | :--- | :--- | :--- | :--- |
| **A** | `fresh_air` (`0x3C`) | Temp: 0°C, Spin: 0, Wind Dispel: ON | Rechazó el ID. Fallback seguro a `cotton` (`0x00`), cargó agua. | **Rechazado** |
| **B** | `single_dehydration` (`0x09`) | Temp: 0°C, Spin: 0, T: 1 min, Wind Dispel: ON | Arrancó bomba de desagote, giró tambor, se apagó al finalizar sin ventilar. | **Fallido** (El flag se ignora en este programa) |
| **C** | `quick_wash` (`0x02`) | Temp: 0°C, Spin: 0, Wash: 0m, Wind Dispel: ON | Ignoró el tiempo 0, cargó agua y empezó ciclo de lavado estándar de 15m. | **Fallido** (Límites rígidos en ciclos mojados) |
| **D** | `time_dry` (`0x82`) o `single_drying` (`0x16`) | Temp: 0°C, Dryer: Level 1 (30m), Wind Dispel: ON | Arrancó a ventilar y girar sin agua, pero **encendió la resistencia de calor** y calentó el tambor. | **Fallido** (No soporta secado en frío) |
| **E** | `steam_care` (`0x6D`) | Temp: 0°C, Spin: 0, Wash: 0m, Wind Dispel: ON | Ignoró el tiempo 0 y comenzó a cargar agua. | **Fallido** (Enfuerza carga de agua) |

---

## 5. Conclusión y Barrera del Firmware
El microcontrolador del lavarropas Midea MF200 posee **reglas de seguridad rígidas grabadas en su firmware** que impiden el bypass lógico:
1. Cualquier programa de lavado (`quick_wash`, `mixed_wash`, `steam_care`) requiere físicamente un nivel mínimo de agua para operar y rechaza los tiempos de lavado fijados en 0.
2. Cualquier programa de secado (`time_dry`, `single_drying`) activa físicamente la resistencia de calefacción por defecto y no permite aireación fría prolongada (el parámetro de temperatura 0°C es ignorado para el calentador).
3. El flag "Aire Fresco" (`wind_dispel`) es una rutina de post-mantenimiento que el firmware solo engancha tras finalizar con éxito un programa de lavado mojado compatible (Algodón, Mezcla, Vapor, etc.). No se puede forzar su ejecución directa de forma autónoma.

---

## 6. Rutas evaluadas y alcance

### A. Intervención de hardware (fuera de alcance)
Alcanzar ventilación en frío por esta vía exigiría intervenir sobre el circuito de potencia de un equipo conectado a 220 V y con agua. Queda fuera del alcance de este trabajo y no se documentan instrucciones: no es una recomendación.

### B. Modificación de Firmware (Invasivo)
* **Propuesta**: Desarmar la placa de control, extraer el firmware de la memoria Flash del microcontrolador (generalmente un chip SPI o MCU Renesas/ARM) y desensamblarlo para parchear los límites de validación de programas o habilitar el ID `0x3C` (`fresh_air` nativo) que está capado de fábrica en esta variante de modelo.
