"""Demo mode: a fake appliance plus a tiny local HTTP server.

The demo exists to show the UX and to produce screenshots. It never opens a
socket to an appliance and the page says so. The frames are still built by
:mod:`mf200.frames`, so what the demo shows is what the real CLI would send.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
from pathlib import Path

from .frames import PROGRAMS, build_control_body, resolve_program
from .presets import PRESETS, get_preset

WEB_DIR = Path(__file__).resolve().parent / "web"
INDEX = WEB_DIR / "index.html"
PROGRAM_NAMES = {value: name for name, value in PROGRAMS.items()}
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


@dataclass
class FakeDevice:
    """In-memory appliance with just enough state for the demo page."""

    power: bool = False
    status: str = "idle"
    program: str = "cotton"
    temperature: str = "default"
    dehydration_speed: str = "default"
    water_level: str = "default"
    time_remaining: int = 0
    progress: str = "idle"
    last_body: str | None = None

    def apply(self, body: bytes) -> None:
        self.power = True
        self.status = "start" if body[2] else "pause"
        self.program = PROGRAM_NAMES.get(body[4], f"0x{body[4]:02X}")
        self.time_remaining = 45
        self.progress = "wash"
        self.last_body = body.hex()

    def stop(self) -> None:
        self.power = False
        self.status = "idle"
        self.progress = "idle"
        self.time_remaining = 0

    def snapshot(self) -> dict:
        return {
            "power": self.power,
            "status": self.status,
            "program": self.program,
            "temperature": self.temperature,
            "dehydration_speed": self.dehydration_speed,
            "water_level": self.water_level,
            "time_remaining": self.time_remaining,
            "progress": self.progress,
            "last_body": self.last_body,
        }


class DemoApp:
    """Stateless HTTP-facing facade over :class:`FakeDevice`."""

    def __init__(self) -> None:
        self.device = FakeDevice()
        self.history: list[dict] = []

    def status(self) -> dict:
        return {"demo": True, **self.device.snapshot()}

    def presets(self) -> list[dict]:
        return [
            {
                "name": name,
                "program": resolve_program(options.program),
                "body": build_control_body(options).hex(),
                "note": "rejected by this firmware" if name == "fresh_air" else "",
            }
            for name, options in sorted(PRESETS.items())
        ]

    def _body(self, payload: dict) -> tuple[str, bytes]:
        name = payload.get("preset")
        if not isinstance(name, str):
            raise ValueError("preset is required")
        base = get_preset(name)
        overrides = {key: payload[key] for key in _OVERRIDES if key in payload}
        return name, build_control_body(replace(base, **overrides))

    def frame(self, payload: dict) -> dict:
        name, body = self._body(payload)
        return {
            "demo": True,
            "preset": name,
            "program": body[4],
            "body": body.hex(),
            "bytes": list(body),
        }

    def run(self, payload: dict) -> dict:
        name, body = self._body(payload)
        self.device.apply(body)
        now = datetime.now().strftime("%H:%M:%S")
        self.history.append({"preset": name, "body": body.hex(), "time": now})
        return {
            "demo": True,
            "sent": True,
            "preset": name,
            "program": body[4],
            "body": body.hex(),
            "time": now,
            "status": self.device.snapshot(),
        }

    def stop(self) -> dict:
        self.device.stop()
        return self.status()


def make_handler(app: DemoApp) -> type[BaseHTTPRequestHandler]:
    """Build a request handler bound to one demo app instance."""

    class Handler(BaseHTTPRequestHandler):
        server_version = "mf200-demo/1.0"

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            pass

        def _send(self, code: int, body: bytes, content_type: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, data: object, code: int = 200) -> None:
            self._send(code, json.dumps(data).encode("utf-8"), "application/json")

        def do_GET(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path
            if path in ("/", "/index.html"):
                self._send(200, INDEX.read_bytes(), "text/html; charset=utf-8")
            elif path == "/api/status":
                self._json(app.status())
            elif path == "/api/presets":
                self._json({"presets": app.presets()})
            elif path == "/api/history":
                self._json({"history": app.history})
            else:
                self._json({"error": "not found"}, 404)

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b"{}"
            try:
                payload = json.loads(raw or b"{}")
            except json.JSONDecodeError:
                self._json({"error": "invalid json"}, 400)
                return
            path = urlsplit(self.path).path
            try:
                if path == "/api/run":
                    self._json(app.run(payload))
                elif path == "/api/frame":
                    self._json(app.frame(payload))
                elif path == "/api/stop":
                    self._json(app.stop())
                else:
                    self._json({"error": "not found"}, 404)
            except (KeyError, ValueError) as exc:
                self._json({"error": str(exc)}, 400)

    return Handler


def serve(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = False) -> None:
    """Serve the demo until interrupted."""
    app = DemoApp()
    server = ThreadingHTTPServer((host, port), make_handler(app))
    url = f"http://{host}:{port}"
    print(f"mf200 demo on {url} — fake device, no appliance is contacted")
    if open_browser:
        import webbrowser

        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
