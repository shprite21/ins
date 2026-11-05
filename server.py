"""Local demonstration server for nonce-based IoT device authentication."""

from __future__ import annotations

import argparse
import base64
import hmac
import json
import secrets
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


CHALLENGE_TTL_SECONDS = 60
AUTH_CONTEXT = b"INS-IOT-AUTH-v1"


def load_devices(path: Path) -> dict[str, bytes]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return {item["device_id"]: bytes.fromhex(item["key_hex"]) for item in data["devices"]}


class AuthState:
    def __init__(self, devices: dict[str, bytes]):
        self.devices = devices
        self.challenges: dict[str, tuple[str, bytes, float]] = {}
        self.lock = threading.Lock()

    def issue(self, device_id: str) -> tuple[str, str] | None:
        if device_id not in self.devices:
            return None
        session_id = secrets.token_urlsafe(18)
        challenge = secrets.token_bytes(32)
        with self.lock:
            self.challenges[session_id] = (device_id, challenge, time.monotonic() + CHALLENGE_TTL_SECONDS)
        return session_id, base64.urlsafe_b64encode(challenge).decode("ascii")

    def verify(self, device_id: str, session_id: str, proof_hex: str) -> bool:
        # Consume first: even an invalid response cannot retry the same challenge.
        with self.lock:
            item = self.challenges.pop(session_id, None)
        if item is None:
            return False
        expected_device, challenge, expires_at = item
        key = self.devices.get(device_id)
        if key is None or expected_device != device_id or time.monotonic() > expires_at:
            return False
        if len(proof_hex) != 64 or any(c not in "0123456789abcdefABCDEF" for c in proof_hex):
            return False
        message = AUTH_CONTEXT + b"|" + device_id.encode("utf-8") + b"|" + session_id.encode("ascii") + b"|" + challenge
        expected = hmac.digest(key, message, "sha256").hex()
        return hmac.compare_digest(expected, proof_hex.lower())


def make_handler(state: AuthState):
    class Handler(BaseHTTPRequestHandler):
        server_version = "INS-IoT-Auth-Demo/1.0"

        def log_message(self, fmt: str, *args: object) -> None:
            print("[auth-server] " + fmt % args)

        def send_json(self, status: int, value: dict[str, object]) -> None:
            body = json.dumps(value, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def read_json(self) -> dict[str, object] | None:
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > 4096:
                    return None
                value = json.loads(self.rfile.read(length))
                return value if isinstance(value, dict) else None
            except (ValueError, json.JSONDecodeError):
                return None

        def do_GET(self) -> None:
            route = urlparse(self.path).path
            if route == "/":
                page = Path(__file__).parent / "web" / "index.html"
                body = page.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
                return
            if route == "/health":
                self.send_json(200, {"status": "ok", "service": "INS-IoT-Auth-Demo"})
                return
            self.send_json(404, {"error": "not_found"})

        def do_POST(self) -> None:
            route = urlparse(self.path).path
            payload = self.read_json()
            if payload is None:
                self.send_json(400, {"error": "invalid_json"})
                return
            if route == "/challenge":
                device_id = payload.get("device_id")
                if not isinstance(device_id, str) or not device_id or len(device_id) > 128:
                    self.send_json(400, {"error": "invalid_device_id"})
                    return
                issued = state.issue(device_id)
                if issued is None:
                    self.send_json(401, {"error": "device_not_registered"})
                    return
                session_id, challenge = issued
                self.send_json(200, {"session_id": session_id, "challenge": challenge, "expires_in": CHALLENGE_TTL_SECONDS})
                return
            if route == "/authenticate":
                device_id, session_id, proof = (payload.get(k) for k in ("device_id", "session_id", "proof"))
                if not all(isinstance(x, str) and x for x in (device_id, session_id, proof)):
                    self.send_json(400, {"error": "invalid_request"})
                    return
                if state.verify(device_id, session_id, proof):
                    self.send_json(200, {"authenticated": True, "device_id": device_id})
                else:
                    self.send_json(401, {"authenticated": False, "error": "authentication_failed"})
                return
            self.send_json(404, {"error": "not_found"})

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the IoT authentication demo server")
    parser.add_argument("--devices", type=Path, default=Path(__file__).parent / "data" / "demo_devices.json")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--tls-cert", type=Path, help="TLS certificate (use with --tls-key)")
    parser.add_argument("--tls-key", type=Path, help="TLS private key (use with --tls-cert)")
    args = parser.parse_args()
    if bool(args.tls_cert) != bool(args.tls_key):
        parser.error("--tls-cert and --tls-key must be supplied together")
    state = AuthState(load_devices(args.devices))
    server = ThreadingHTTPServer((args.host, args.port), make_handler(state))
    scheme = "http"
    if args.tls_cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.tls_cert, args.tls_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        scheme = "https"
    print(f"IoT auth demo listening on {scheme}://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
