# Protocol map

Everything below was derived from the device itself: status frames captured
before and after each action in the official app, then confirmed against the
vendor's own Lua and JavaScript register definitions.

## Frames

| Frame | Direction | Size |
|---|---|---|
| Status | device to client | ~52 bytes |
| Control | client to device | 22-byte body |

Control frames carry only what the caller wants to change. Any option left at
`0xFF` is ignored by the firmware, which is what makes partial control frames
possible at all.

## Bits

| Feature | Direction | Byte | Bit | Encoding |
|---|---|---|---|---|
| `wind_dispel` (fresh air) | read | 39 (`body[29]`) | 6 | `0x80` off, `0xC0` on |
| `wind_dispel` (fresh air) | write | 29 (`body[19]`) | 0 | `0x01` |
| `steam_wash` | write | 26 (`body[16]`) | 4 | `0x10` |

The byte numbers on the left are absolute in the frame; the bracket notation is
the index inside the body, which is what the code uses.

## Reading versus writing

The same feature sits at different positions depending on direction. A reader
who assumes the status and control frames share a layout will write to the wrong
byte, and the firmware will accept the frame silently because the option at that
position is a valid one. That failure mode is quiet, and it cost most of the time
spent on this investigation.

## Program identifiers

| Name | Identifier | Notes |
|---|---|---|
| `cotton` | `0x00` | default, always available |
| `quick_wash` | `0x02` | rejects zero wash time |
| `single_dehydration` | `0x09` | drains, no ventilation |
| `single_drying` | `0x16` | energises the heater |
| `fresh_air` | `0x3C` | defined, blocked in this regional firmware |
| `steam_care` | `0x6D` | forces a water load |
| `time_dry` | `0x82` | energises the heater |
