"""Build the 22-byte control body used by the Midea DB local protocol.

Only the bytes the caller wants to change are set: every other byte stays at
``0xFF``, which the firmware ignores. That is what makes partial control
frames possible at all and what keeps a "start" command from silently
changing temperature, spin or water level.

The layout is the one documented in ``docs/protocol-map.md`` and exercised by
``tools/07_test_raw_program.py``. It is not the same layout as the status
frame.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

BODY_SIZE = 22
IGNORE = 0xFF
SET_COMMAND = 0x02
MAX_VALUE = 0xFE

#: Program identifiers verified against this firmware. Other DB models expose
#: more programs; pass a raw id to use one that is not listed here.
PROGRAMS: dict[str, int] = {
    "cotton": 0x00,
    "eco": 0x01,
    "quick_wash": 0x02,
    "mixed_wash": 0x03,
    "wool": 0x04,
    "synthetic": 0x05,
    "rinse_spin": 0x08,
    "single_dehydration": 0x09,
    "air_wash": 0x15,
    "single_drying": 0x16,
    "fresh_air": 0x3C,
    "bucket_dry": 0x3D,
    "baby_care": 0x64,
    "jeans": 0x67,
    "fresh_remove_wrinkle": 0x69,
    "outdoor": 0x6A,
    "down_jacket": 0x6B,
    "steam_care": 0x6D,
    "time_dry": 0x82,
}

#: Celsius to protocol code. Codes not listed are unknown for this device.
TEMPERATURE_CODES: dict[int, int] = {
    0: 0x01,
    20: 0x02,
    30: 0x03,
    40: 0x04,
    60: 0x05,
    70: 0x07,
    95: 0x06,
}

#: Revolutions per minute to protocol code.
SPIN_CODES: dict[int, int] = {
    0: 0x00,
    400: 0x01,
    600: 0x02,
    800: 0x03,
    1000: 0x04,
    1200: 0x05,
    1300: 0x08,
    1400: 0x06,
    1600: 0x07,
}

#: Water level labels to protocol codes.
WATER_LEVEL_CODES: dict[str, int] = {
    "low": 0x01,
    "mid": 0x02,
    "high": 0x03,
    "4": 0x04,
    "auto": 0x05,
}


class Field(IntEnum):
    """Byte offsets inside the control body."""

    CONTROL_TYPE = 0
    POWER = 1
    START = 2
    MODE = 3
    PROGRAM = 4
    WATER_LEVEL = 5
    DRYER_LEVEL = 6
    TEMPERATURE = 7
    SPIN_SPEED = 8
    WASH_TIME = 9
    SPIN_TIME = 10
    DETERGENT = 11
    SOFTENER = 12
    FLAGS_13 = 13
    APPOINTMENT_LO = 14
    APPOINTMENT_HI = 15
    FLAGS_16 = 16
    STAINS = 17
    DIRTY_DEGREE = 18
    FLAGS_19 = 19
    COMPLEX_KEY = 20
    RESERVED = 21


@dataclass(frozen=True)
class ControlOptions:
    """What to put in a control frame.

    ``None`` (and ``False`` for the flags) means "do not touch this byte":
    the firmware keeps its default. Values are protocol-level and the
    helpers translate the friendly ones (Celsius, RPM, level names).
    """

    program: int | str
    start: bool = True
    power: bool | None = None
    temperature: int | None = None
    spin_rpm: int | None = None
    wash_minutes: int | None = None
    spin_minutes: int | None = None
    water_level: str | int | None = None
    dryer_level: int | None = None
    steam: bool = False
    air_fresh: bool = False
    spray: bool = False
    detergent: int | None = None
    softener: int | None = None


def _check_value(value: int, name: str, maximum: int = MAX_VALUE) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer, got {value!r}")
    if not 0 <= value <= maximum:
        raise ValueError(f"{name} must be between 0 and {maximum}, got {value}")
    return value


def resolve_program(program: int | str) -> int:
    """Return the one-byte program id for a name or a raw id."""
    if isinstance(program, str):
        try:
            return PROGRAMS[program]
        except KeyError:
            known = ", ".join(sorted(PROGRAMS))
            raise ValueError(
                f"unknown program {program!r}; known names: {known}"
            ) from None
    if isinstance(program, bool) or not isinstance(program, int):
        raise ValueError(f"program must be a name or an integer, got {program!r}")
    if not 0 <= program <= 0xFF:
        raise ValueError(f"program must fit in one byte, got {program}")
    return program


def _temperature_code(celsius: int) -> int:
    try:
        return TEMPERATURE_CODES[celsius]
    except KeyError:
        allowed = ", ".join(str(value) for value in sorted(TEMPERATURE_CODES))
        raise ValueError(f"unsupported temperature {celsius}C; use one of: {allowed}") from None


def _spin_code(rpm: int) -> int:
    try:
        return SPIN_CODES[rpm]
    except KeyError:
        allowed = ", ".join(str(value) for value in sorted(SPIN_CODES))
        raise ValueError(f"unsupported spin speed {rpm} rpm; use one of: {allowed}") from None


def _water_level_code(level: str | int) -> int:
    if isinstance(level, str):
        try:
            return WATER_LEVEL_CODES[level]
        except KeyError:
            allowed = ", ".join(sorted(WATER_LEVEL_CODES))
            raise ValueError(
                f"unknown water level {level!r}; use one of: {allowed}"
            ) from None
    return _check_value(level, "water_level")


def build_control_body(options: ControlOptions) -> bytes:
    """Encode a :class:`ControlOptions` into the 22-byte control body."""
    body = bytearray([IGNORE] * BODY_SIZE)
    body[Field.CONTROL_TYPE] = SET_COMMAND
    body[Field.PROGRAM] = resolve_program(options.program)
    body[Field.START] = 0x01 if options.start else 0x00

    if options.power is not None:
        body[Field.POWER] = 0x01 if options.power else 0x00
    if options.temperature is not None:
        body[Field.TEMPERATURE] = _temperature_code(options.temperature)
    if options.spin_rpm is not None:
        body[Field.SPIN_SPEED] = _spin_code(options.spin_rpm)
    if options.wash_minutes is not None:
        body[Field.WASH_TIME] = _check_value(options.wash_minutes, "wash_minutes")
    if options.spin_minutes is not None:
        body[Field.SPIN_TIME] = _check_value(options.spin_minutes, "spin_minutes")
    if options.water_level is not None:
        body[Field.WATER_LEVEL] = _water_level_code(options.water_level)
    if options.dryer_level is not None:
        if not 0 <= options.dryer_level <= 3:
            raise ValueError(
                f"dryer_level must be between 0 and 3, got {options.dryer_level}"
            )
        body[Field.DRYER_LEVEL] = options.dryer_level
    if options.detergent is not None:
        body[Field.DETERGENT] = _check_value(options.detergent, "detergent")
    if options.softener is not None:
        body[Field.SOFTENER] = _check_value(options.softener, "softener")

    if options.spray:
        body[Field.FLAGS_13] = 0x04
    if options.steam:
        body[Field.FLAGS_16] = 0x10
    if options.air_fresh:
        body[Field.FLAGS_19] = 0x01

    return bytes(body)
