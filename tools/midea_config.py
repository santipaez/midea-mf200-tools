"""Device configuration, read from the environment.

Nothing here is committed: copy `.env.example` to `.env` and set your own
device address, or export the variables before running any script.
"""

from __future__ import annotations

import ipaddress
import os


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(
            f"{name} is not set. Export it first, for example:\n"
            f"    export {name}=192.168.1.50"
        )
    return value


def device_ip() -> str:
    return _required("MIDEA_DEVICE_IP")


def broadcast_ip() -> str:
    """The /24 broadcast for the device subnet, derived rather than hardcoded."""
    explicit = os.environ.get("MIDEA_BROADCAST_IP", "").strip()
    if explicit:
        return explicit
    return str(ipaddress.ip_network(f"{device_ip()}/24", strict=False).broadcast_address)


DEVICE_IP = device_ip
BROADCAST_IP = broadcast_ip
