"""Transport for the Midea MF200 over the local V3 protocol.

This module is the only one that imports ``midea-local``. Importing it is safe
without the library installed: the import happens inside :meth:`Device.connect`,
so the frame builder and the CLI's dry run work on any machine.

The credentials come from ``tools/results/credentials.json``, the file that
``tools/04_read_raw_bytes.py`` produces. They are never copied into this
package.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_CREDENTIALS = (
    Path(__file__).resolve().parents[1] / "tools" / "results" / "credentials.json"
)

_STATUS_ATTRIBUTES = (
    "power",
    "start",
    "status",
    "mode",
    "program",
    "water_level",
    "temperature",
    "dehydration_speed",
    "wash_time",
    "dehydration_time",
    "time_remaining",
    "progress",
)


@dataclass(frozen=True)
class Credentials:
    """Device identity and keys produced by the discovery phase."""

    device_id: int
    token: str
    key: str

    @classmethod
    def load(cls, path: str | Path | None = None) -> Credentials:
        location = Path(path) if path is not None else DEFAULT_CREDENTIALS
        if not location.exists():
            raise FileNotFoundError(
                f"{location} not found; run tools/04_read_raw_bytes.py first "
                "or pass --credentials"
            )
        data = json.loads(location.read_text(encoding="utf-8"))
        return cls(
            device_id=int(data["device_id"]),
            token=data["token"],
            key=data["key"],
        )


class Device:
    """One connection to the appliance.

    The class is intentionally thin: it refreshes status, powers the machine on
    when needed, and injects the 22-byte body built by :mod:`mf200.frames`.
    """

    def __init__(
        self,
        ip: str,
        credentials: Credentials,
        model: str | None = None,
        port: int = 6444,
    ) -> None:
        self.ip = ip
        self.credentials = credentials
        self.model = model
        self.port = port
        self.captured: bytes | None = None
        self._device: Any = None

    def connect(self) -> None:
        """Discover the appliance and complete the V3 handshake."""
        from midealocal.const import ProtocolVersion
        from midealocal.discover import discover
        from midealocal.devices.db import MideaDBDevice

        devices = discover(ip_address=self.ip)
        if not devices:
            raise ConnectionError(
                f"no Midea appliance answered at {self.ip}; check "
                "MIDEA_DEVICE_IP and that the machine is on the same network"
            )
        info = next(iter(devices.values()))

        outer = self

        class CapturingDevice(MideaDBDevice):
            """DB device that keeps the last raw response for callers/tests."""

            def process_message(inner, msg: bytes, *args: Any, **kwargs: Any) -> dict:
                outer.captured = bytes(msg)
                return super().process_message(msg)

        self._device = CapturingDevice(
            name="midea_db",
            device_id=self.credentials.device_id,
            ip_address=self.ip,
            port=self.port,
            token=self.credentials.token,
            key=self.credentials.key,
            device_protocol=ProtocolVersion.V3,
            model=self.model or info.get("model", ""),
            subtype=0,
            customize="",
        )
        if not self._device.connect():
            raise ConnectionError("the appliance did not accept the local connection")

    def _require(self) -> Any:
        if self._device is None:
            raise RuntimeError("call connect() before using the device")
        return self._device

    def status(self) -> dict[str, Any]:
        """Refresh and return the attributes the UI cares about."""
        device = self._require()
        device.refresh_status(check_protocol=True)
        return {
            attribute: device.get_attribute(attribute)
            for attribute in _STATUS_ATTRIBUTES
        }

    def send(self, body: bytes) -> None:
        """Power the machine on if needed and inject one control body."""
        device = self._require()
        device.refresh_status(check_protocol=True)
        if not device.get_attribute("power"):
            device.set_attribute("power", True)
            time.sleep(2.0)
            device.refresh_status(check_protocol=True)
        self._send_custom(device, body)

    def _send_custom(self, device: Any, body: bytes) -> None:
        """Serialize and encrypt one custom set frame (same path as tools/07)."""
        from midealocal.message import MessageQuestCustom, MessageType
        from midealocal.packet_builder import PacketBuilder
        from midealocal.security import MSGTYPE_ENCRYPTED_REQUEST

        command = MessageQuestCustom(
            device.device_type,
            device._message_protocol_version,
            MessageType.set,
            bytearray(body),
        )
        data = command.serialize()
        message = PacketBuilder(device.device_id, data).finalize()
        encrypted = device._security.encode_8370(message, MSGTYPE_ENCRYPTED_REQUEST)
        device.send_message(encrypted)

    def close(self) -> None:
        """Close the socket, ignoring an already closed connection."""
        if self._device is not None:
            try:
                self._device.close_socket()
            finally:
                self._device = None
