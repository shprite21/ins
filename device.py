"""Device simulator that proves possession of a provisioned symmetric key."""

from __future__ import annotations

import argparse
import base64
import hmac
import json
import urllib.error
import urllib.request
from pathlib import Path

from server import AUTH_CONTEXT


def post_json(base_url: str, route: str, value: dict[str, str]) -> dict[str, object]:
    body = json.dumps(value).encode("utf-8")
    request = urllib.request.Request(
        base_url.rstrip("/") + route,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            details = json.loads(exc.read().decode("utf-8"))
        except (ValueError, json.JSONDecodeError):
            details = {"error": str(exc)}
        raise RuntimeError(f"server rejected request: {details}") from exc


def main() -> None:
    parser = argparse.ArgumentParser(description="Authenticate the demo IoT device")
    parser.add_argument("device_id", nargs="?", default="sensor-001")
    parser.add_argument("--server", default="http://127.0.0.1:8080")
    parser.add_argument("--devices", type=Path, default=Path(__file__).parent / "data" / "demo_devices.json")
    args = parser.parse_args()
    data = json.loads(args.devices.read_text(encoding="utf-8"))
    key_map = {item["device_id"]: bytes.fromhex(item["key_hex"]) for item in data["devices"]}
    key = key_map.get(args.device_id)
    if key is None:
        raise SystemExit(f"No local key provisioned for {args.device_id!r}")

    issued = post_json(args.server, "/challenge", {"device_id": args.device_id})
    session_id = str(issued["session_id"])
    challenge = base64.urlsafe_b64decode(str(issued["challenge"]).encode("ascii"))
    message = AUTH_CONTEXT + b"|" + args.device_id.encode("utf-8") + b"|" + session_id.encode("ascii") + b"|" + challenge
    proof = hmac.digest(key, message, "sha256").hex()
    result = post_json(args.server, "/authenticate", {
        "device_id": args.device_id,
        "session_id": session_id,
        "proof": proof,
    })
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
