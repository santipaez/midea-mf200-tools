"""Named wash programs the device is known to run.

The presets intentionally leave temperature, spin, water level and times at
the firmware default: the protocol map only proves the *program* ids and the
three feature bits, and guessing the rest would produce frames that look
right and behave wrong. Use :class:`mf200.frames.ControlOptions` to override
any of them.
"""

from __future__ import annotations

from .frames import ControlOptions, build_control_body

PRESETS: dict[str, ControlOptions] = {
    "cotton": ControlOptions(program="cotton"),
    "quick": ControlOptions(program="quick_wash"),
    "mixed": ControlOptions(program="mixed_wash"),
    "wool": ControlOptions(program="wool"),
    "rinse_spin": ControlOptions(program="rinse_spin"),
    "spin": ControlOptions(program="single_dehydration"),
    "dry": ControlOptions(program="single_drying"),
    "steam": ControlOptions(program="steam_care", steam=True),
    # Defined and rejected by this regional firmware; kept as a reproducible
    # probe, not as a supported wash.
    "fresh_air": ControlOptions(program="fresh_air", air_fresh=True),
}


def get_preset(name: str) -> ControlOptions:
    """Return a preset by name, raising ``KeyError`` when it does not exist."""
    try:
        return PRESETS[name]
    except KeyError:
        known = ", ".join(sorted(PRESETS))
        raise KeyError(f"unknown preset {name!r}; known presets: {known}") from None


def build_preset_body(name: str) -> bytes:
    """Build the control body for a named preset."""
    return build_control_body(get_preset(name))
