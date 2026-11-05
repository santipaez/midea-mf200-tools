# Control frame, byte by byte

This is the full map of the 22-byte body the firmware accepts as a control
frame. It is the reference implementation behind `mf200/frames.py` and the
reason someone can port the layer to another language without reading Python.

The status frame is a different layout; do not assume the offsets line up.
See [protocol-map.md](protocol-map.md) for the read/write asymmetry.

## Rule zero: 0xFF means "leave it alone"

A control frame only carries what the caller wants to change. Every byte left
at `0xFF` is ignored by the firmware, so a frame with one program id and two
feature bits is valid and does not reset temperature, spin or water level.

## The 22 bytes

| Index | Field | Notes |
|---|---|---|
| 0 | control type | `0x02` for a set command |
| 1 | power | `0x01` on, `0x00` off, `0xFF` leave alone |
| 2 | start/pause | `0x01` start, `0x00` pause |
| 3 | mode | `0xFF` in every frame this repo sends |
| 4 | program | see [program ids](#program-ids) |
| 5 | water level | `0x01` low, `0x02` mid, `0x03` high, `0x04` 4, `0x05` auto |
| 6 | dryer level | `0x00`–`0x03` |
| 7 | temperature | see [temperature codes](#temperature-codes) |
| 8 | spin speed | see [spin codes](#spin-codes) |
| 9 | wash time | minutes, `0x00`–`0xFE` |
| 10 | spin time | minutes, `0x00`–`0xFE` |
| 11 | detergent | `0x00`–`0xFE` |
| 12 | softener | `0x00`–`0xFE` |
| 13 | flag byte | bit 2 (`0x04`) = spray wash |
| 14 | appointment low | unused here; encoding not verified |
| 15 | appointment high | unused here; encoding not verified |
| 16 | flag byte | bit 4 (`0x10`) = steam wash |
| 17 | stains | `0xFF` |
| 18 | dirty degree | `0xFF` |
| 19 | flag byte | bit 0 (`0x01`) = air fresh (`wind_dispel`) |
| 20 | complex key | `0xFF` |
| 21 | reserved | `0xFF` |

## Program ids

Verified against this firmware and used by the presets. Other DB models expose
more ids; `mf200` accepts a raw integer for those.

| Name | Id |
|---|---|
| cotton | `0x00` |
| eco | `0x01` |
| quick_wash | `0x02` |
| mixed_wash | `0x03` |
| wool | `0x04` |
| synthetic | `0x05` |
| rinse_spin | `0x08` |
| single_dehydration | `0x09` |
| air_wash | `0x15` |
| single_drying | `0x16` |
| fresh_air | `0x3C` — defined, rejected by this regional firmware |
| bucket_dry | `0x3D` |
| baby_care | `0x64` |
| jeans | `0x67` |
| fresh_remove_wrinkle | `0x69` |
| outdoor | `0x6A` |
| down_jacket | `0x6B` |
| steam_care | `0x6D` |
| time_dry | `0x82` |

## Temperature codes

| Celsius | Code |
|---|---|
| 0 | `0x01` |
| 20 | `0x02` |
| 30 | `0x03` |
| 40 | `0x04` |
| 60 | `0x05` |
| 95 | `0x06` |
| 70 | `0x07` |

Codes not listed are unverified on this device. The builder raises instead of
guessing.

## Spin codes

| RPM | Code |
|---|---|
| 0 | `0x00` |
| 400 | `0x01` |
| 600 | `0x02` |
| 800 | `0x03` |
| 1000 | `0x04` |
| 1200 | `0x05` |
| 1400 | `0x06` |
| 1600 | `0x07` |
| 1300 | `0x08` |

## Worked example

`python -m mf200 frame quick --temperature 40 --spin 800` produces:

```
02 ff 01 ff 02 ff ff 04 03 ff ff ff ff ff ff ff ff ff ff ff ff ff
```

Reading it back: set command (`02`), power untouched (`ff`), start (`01`),
mode untouched (`ff`), program `quick_wash` (`02`), water untouched (`ff`),
dryer untouched (`ff`), 40 °C (`04`), 800 rpm (`03`), everything else left to
the firmware.

## Transport

This document stops at the body. The framing around it (checksum, `0xAA`
packet, V3 encryption, TCP `6444`) is handled by `midea-local` and is not
reimplemented here. If you port this to another language, reuse an existing
V3 transport rather than rebuilding the crypto.

## Porting checklist

1. Build a 22-byte array filled with `0xFF`.
2. Set byte 0 to `0x02`, byte 2 to `0x01` for start (or `0x00` for pause),
   byte 4 to the program id.
3. Set only the option bytes you mean to change.
4. Send it through a working V3 transport, powering the machine on first if
   needed.
5. Read the status frame after two or three seconds and check the program it
   reports; the firmware silently falls back to cotton for ids it rejects.
