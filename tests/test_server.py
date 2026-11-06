"""Regression tests for report behavior; no third-party dependencies."""

import base64
from concurrent.futures import ThreadPoolExecutor
import hmac
import http.client
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import threading
import unittest
from unittest.mock import patch

from server import AUTH_CONTEXT, AuthState, load_devices, make_handler


ROOT = Path(__file__).resolve().parents[1]
KEYS = load_devices(ROOT / "data" / "demo_devices.json")


def proof(device_id, session_id, challenge):
    message = (AUTH_CONTEXT + b"|" + device_id.encode() + b"|"
               + session_id.encode() + b"|" + base64.urlsafe_b64decode(challenge))
    return hmac.digest(KEYS[device_id], message, "sha256").hex()


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state = AuthState(KEYS)
        handler = make_handler(cls.state)
        handler.log_message = lambda *args: None
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def request(self, path, value=None, raw=None):
        client = http.client.HTTPConnection(*self.server.server_address, timeout=5)
        try:
            method = "GET" if value is None and raw is None else "POST"
            body = raw if raw is not None else json.dumps(value).encode() if value is not None else None
            client.request(method, path, body=body, headers={"Content-Type": "application/json"})
            response = client.getresponse()
            data = response.read()
            return response.status, data, response.getheader("Content-Type")
        finally:
            client.close()

    def post(self, path, value):
        status, data, _ = self.request(path, value)
        return status, json.loads(data)

    def session(self):
        status, data = self.post("/challenge", {"device_id": "sensor-001"})
        self.assertEqual(status, 200)
        return data

    def payload(self, session):
        return {"device_id": "sensor-001", "session_id": session["session_id"],
                "proof": proof("sensor-001", session["session_id"], session["challenge"])}

    def test_valid_devices_and_replay(self):
        for device_id in KEYS:
            status, session = self.post("/challenge", {"device_id": device_id})
            self.assertEqual(status, 200)
            payload = {"device_id": device_id, "session_id": session["session_id"],
                       "proof": proof(device_id, session["session_id"], session["challenge"])}
            self.assertEqual(self.post("/authenticate", payload), (200, {"authenticated": True, "device_id": device_id}))
            self.assertEqual(self.post("/authenticate", payload)[0], 401)

    def test_unknown_identity_has_no_challenge(self):
        self.assertEqual(self.post("/challenge", {"device_id": "unknown"}), (401, {"error": "device_not_registered"}))

    def test_tampered_proof_consumes_session(self):
        session = self.session()
        original = self.payload(session)
        bad = dict(original, proof=("0" if original["proof"][0] != "0" else "1") + original["proof"][1:])
        self.assertEqual(self.post("/authenticate", bad)[0], 401)
        self.assertEqual(self.post("/authenticate", original)[0], 401)

    def test_expired_proof_rejected(self):
        state = AuthState(KEYS)
        with patch("server.time.monotonic", return_value=100):
            session_id, challenge = state.issue("sensor-001")
        with patch("server.time.monotonic", return_value=161):
            self.assertFalse(state.verify("sensor-001", session_id, proof("sensor-001", session_id, challenge)))
        self.assertNotIn(session_id, state.challenges)

    def test_concurrent_verification_accepts_at_most_once(self):
        state = AuthState(KEYS)
        session_id, challenge = state.issue("sensor-001")
        value = proof("sensor-001", session_id, challenge)
        with ThreadPoolExecutor(max_workers=12) as pool:
            outcomes = list(pool.map(lambda _: state.verify("sensor-001", session_id, value), range(12)))
        self.assertEqual(sum(outcomes), 1)

    def test_freshness_and_context_binding(self):
        first, second = self.session(), self.session()
        self.assertEqual(len(base64.urlsafe_b64decode(first["challenge"])), 32)
        self.assertEqual(first["expires_in"], 60)
        self.assertNotEqual(first["session_id"], second["session_id"])
        self.assertNotEqual(first["challenge"], second["challenge"])
        wrong_device = {"device_id": "sensor-002", "session_id": first["session_id"],
                        "proof": proof("sensor-002", first["session_id"], first["challenge"])}
        self.assertEqual(self.post("/authenticate", wrong_device)[0], 401)
        wrong_session = self.payload(second)
        wrong_session["session_id"] += "-changed"
        self.assertEqual(self.post("/authenticate", wrong_session)[0], 401)
        changed = bytearray(base64.urlsafe_b64decode(second["challenge"]))
        changed[0] ^= 1
        changed_payload = self.payload(second)
        changed_payload["proof"] = proof("sensor-001", second["session_id"], base64.urlsafe_b64encode(changed))
        self.assertEqual(self.post("/authenticate", changed_payload)[0], 401)

    def test_malformed_requests_including_invalid_utf8(self):
        for route in ("/challenge", "/authenticate"):
            for body in (b"{}", b"{invalid", b"[]", b"null", b"\xff", b"", b"x" * 4097):
                with self.subTest(route=route, body=body[:20]):
                    status, data, _ = self.request(route, raw=body)
                    self.assertEqual(status, 400)
                    self.assertIn("error", json.loads(data))
        self.assertEqual(self.post("/challenge", {"device_id": 42})[0], 400)
        self.assertEqual(self.post("/authenticate", {"device_id": "sensor-001", "session_id": 42, "proof": "a"})[0], 400)

    def test_metadata_excludes_secrets_and_serves_report(self):
        status, data, _ = self.request("/demo/info")
        self.assertEqual(status, 200)
        info = json.loads(data)
        self.assertEqual(info["device_ids"], sorted(KEYS))
        self.assertEqual(info["transport"], "http")
        for key in KEYS.values():
            self.assertNotIn(key.hex().encode(), data)
        status, data, content_type = self.request("/report")
        self.assertEqual(status, 200)
        self.assertEqual(content_type, "application/pdf")
        self.assertEqual(data, (ROOT / "report" / "Secure_Authentication_for_IoT_Devices_CCA_Report.pdf").read_bytes())
        self.assertEqual(self.request("/report/../../server.py")[0], 404)


if __name__ == "__main__":
    unittest.main()
