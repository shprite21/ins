"""ST-7: validate TLS trust and device authentication without changing OS trust."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hmac
import json
from pathlib import Path
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

from server import AUTH_CONTEXT, load_devices


def request_json(base_url: str, path: str, context: ssl.SSLContext,
                 payload: dict[str, str] | None = None) -> dict:
    # A direct local connection keeps proxy configuration from changing the test.
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context)
    )
    request = urllib.request.Request(
        base_url + path,
        data=json.dumps(payload).encode("utf-8") if payload is not None else None,
        headers={"Content-Type": "application/json"} if payload is not None else {},
    )
    with opener.open(request, timeout=10) as response:
        if response.status != 200:
            raise RuntimeError(f"Unexpected HTTP {response.status}")
        # Do not allow a redirect to turn the HTTPS check into a different target.
        if response.url != base_url + path:
            raise RuntimeError("Unexpected redirect during TLS check")
        return json.load(response)


def verify(server: str, ca_file: Path, untrusted_ca_file: Path,
           devices_file: Path) -> dict:
    result = {
        "schema": "INS-IOT-TLS-CHECK-v1",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "server": server,
        "trusted_authentication": False,
        "untrusted_certificate_rejected": False,
        "errors": [],
    }
    try:
        trusted = ssl.create_default_context(cafile=str(ca_file))
        info = request_json(server, "/demo/info", trusted)
        if info.get("transport") != "https":
            raise RuntimeError("Server did not report a TLS connection")
        result["tls_version"] = info.get("tls_version")
        keys = load_devices(devices_file)
        device_id = "sensor-001"
        issued = request_json(server, "/challenge", trusted, {"device_id": device_id})
        message = (AUTH_CONTEXT + b"|" + device_id.encode("utf-8") + b"|"
                   + issued["session_id"].encode("ascii") + b"|"
                   + base64.urlsafe_b64decode(issued["challenge"]))
        proof = hmac.digest(keys[device_id], message, "sha256").hex()
        outcome = request_json(server, "/authenticate", trusted, {
            "device_id": device_id, "session_id": issued["session_id"], "proof": proof,
        })
        if outcome.get("authenticated") is not True or outcome.get("device_id") != device_id:
            raise RuntimeError("Trusted TLS connection did not authenticate sensor-001")
        result["trusted_authentication"] = True
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        result["errors"].append(f"Trusted authentication: {error}")

    try:
        untrusted = ssl.create_default_context(cafile=str(untrusted_ca_file))
        request_json(server, "/health", untrusted)
        result["errors"].append("Unrelated CA unexpectedly trusted the server certificate")
    except urllib.error.URLError as error:
        if isinstance(error.reason, ssl.SSLCertVerificationError):
            result["untrusted_certificate_rejected"] = True
        else:
            result["errors"].append(f"Untrusted check failed without certificate rejection: {error}")
    except ssl.SSLCertVerificationError:
        result["untrusted_certificate_rejected"] = True
    except (OSError, ValueError, RuntimeError) as error:
        result["errors"].append(f"Untrusted check: {error}")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True)
    parser.add_argument("--ca-file", type=Path, required=True)
    parser.add_argument("--untrusted-ca-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, help="Write UTF-8 JSON evidence for dashboard import")
    parser.add_argument("--devices", type=Path, default=Path(__file__).parent / "data" / "demo_devices.json")
    args = parser.parse_args()
    url = urllib.parse.urlsplit(args.server)
    if (url.scheme != "https" or not url.hostname or url.username or url.password
            or url.path not in ("", "/") or url.query or url.fragment):
        parser.error("--server must be an HTTPS origin, such as https://127.0.0.1:8443")
    result = verify(args.server.rstrip("/"), args.ca_file, args.untrusted_ca_file, args.devices)
    output = json.dumps(result, indent=2)
    if args.output:
        args.output.write_text(output + "\n", encoding="utf-8")
    print(output)
    return 0 if result["trusted_authentication"] and result["untrusted_certificate_rejected"] else 1


if __name__ == "__main__":
    sys.exit(main())
