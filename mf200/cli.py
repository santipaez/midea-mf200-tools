"""Command line interface for the MF200 control layer.

``frame`` and ``presets`` work offline. ``run`` and ``status`` need the
appliance and ``midea-local``; use ``--dry-run`` to see the exact bytes that
would be injected without connecting.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import replace

from .frames import ControlOptions, build_control_body, resolve_program
from .presets import PRESETS, get_preset

_OVERRIDES = (
    "temperature",
    "spin_rpm",
    "wash_minutes",
    "spin_minutes",
    "water_level",
    "dryer_level",
    "steam",
    "air_fresh",
    "spray",
)


def _add_overrides(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--temperature", type=int, help="wash temperature in Celsius")
    parser.add_argument("--spin", dest="spin_rpm", type=int, help="final spin in RPM")
    parser.add_argument("--wash-minutes", type=int, help="wash time in minutes")
    parser.add_argument("--spin-minutes", type=int, help="spin time in minutes")
    parser.add_argument(
        "--water",
        dest="water_level",
        choices=["low", "mid", "high", "4", "auto"],
        help="water level",
    )
    parser.add_argument(
        "--dryer-level", type=int, choices=range(4), help="drying intensity, 0-3"
    )
    parser.add_argument("--steam", action="store_true", default=None)
    parser.add_argument("--air-fresh", dest="air_fresh", action="store_true", default=None)
    parser.add_argument("--spray", action="store_true", default=None)
    parser.add_argument("--json", action="store_true", help="machine-readable output")


def _options(args: argparse.Namespace) -> ControlOptions:
    base = get_preset(args.preset)
    changes = {
        name: getattr(args, name)
        for name in _OVERRIDES
        if getattr(args, name, None) is not None
    }
    return replace(base, **changes)


def _frame_payload(preset: str, body: bytes, **extra: object) -> dict:
    payload = {
        "preset": preset,
        "program": body[4],
        "body": body.hex(),
        "bytes": list(body),
    }
    payload.update(extra)
    return payload


def _print_frame(preset: str, body: bytes, as_json: bool, **extra: object) -> None:
    if as_json:
        print(json.dumps(_frame_payload(preset, body, **extra)))
        return
    print(f"{preset}: {body.hex()}")
    for index, value in enumerate(body):
        print(f"  [{index:02d}] 0x{value:02X}")


def _connect(args: argparse.Namespace):
    from .device import Credentials, Device

    ip = args.ip or os.environ.get("MIDEA_DEVICE_IP", "").strip()
    if not ip:
        raise ValueError("MIDEA_DEVICE_IP is not set; pass --ip or export it")
    device = Device(ip, Credentials.load(args.credentials))
    device.connect()
    return device


def _cmd_presets(args: argparse.Namespace) -> int:
    for name in sorted(PRESETS):
        program = resolve_program(PRESETS[name].program)
        print(f"{name:20} 0x{program:02X}")
    return 0


def _cmd_frame(args: argparse.Namespace) -> int:
    body = build_control_body(_options(args))
    _print_frame(args.preset, body, args.json)
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    body = build_control_body(_options(args))
    if args.dry_run:
        _print_frame(args.preset, body, args.json, sent=False, dry_run=True)
        return 0

    device = _connect(args)
    try:
        device.send(body)
        status = device.status()
    finally:
        device.close()
    _print_frame(args.preset, body, args.json, sent=True, dry_run=False, status=status)
    return 0


def _cmd_status(args: argparse.Namespace) -> int:
    device = _connect(args)
    try:
        status = device.status()
    finally:
        device.close()
    print(json.dumps(status, indent=2, default=str))
    return 0


def _cmd_demo(args: argparse.Namespace) -> int:
    from .demo import serve

    serve(args.host, args.port, args.open)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mf200",
        description="Build and send Midea DB control frames over the local network.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    presets = subparsers.add_parser("presets", help="list the named programs")
    presets.set_defaults(func=_cmd_presets)

    frame = subparsers.add_parser("frame", help="print the control body for a preset")
    frame.add_argument("preset")
    _add_overrides(frame)
    frame.set_defaults(func=_cmd_frame)

    run = subparsers.add_parser("run", help="send a preset to the appliance")
    run.add_argument("preset")
    _add_overrides(run)
    run.add_argument("--dry-run", action="store_true", help="do not connect")
    run.add_argument("--ip", help="appliance address (or MIDEA_DEVICE_IP)")
    run.add_argument("--credentials", help="path to credentials.json")
    run.set_defaults(func=_cmd_run)

    status = subparsers.add_parser("status", help="read the current state")
    status.add_argument("--ip", help="appliance address (or MIDEA_DEVICE_IP)")
    status.add_argument("--credentials", help="path to credentials.json")
    status.set_defaults(func=_cmd_status)

    demo = subparsers.add_parser("demo", help="serve the UI against a fake device")
    demo.add_argument("--host", default="127.0.0.1")
    demo.add_argument("--port", type=int, default=8765)
    demo.add_argument("--open", action="store_true", help="open the page in a browser")
    demo.set_defaults(func=_cmd_demo)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, KeyError, FileNotFoundError, ConnectionError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
