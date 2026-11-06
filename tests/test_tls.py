"""Optional TLS regression with ephemeral certificates, never OS trust changes."""

from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
import importlib.util
import ipaddress
import json
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest

from server import AuthState, load_devices, make_handler
from verify_tls import verify


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(importlib.util.find_spec("cryptography"), "Optional test dependency: cryptography")
class TLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        cls.temp = tempfile.TemporaryDirectory(prefix="iot-tls-test-")
        cls.folder = Path(cls.temp.name)
        now = datetime.now(timezone.utc)

        def authority(name):
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
            cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                    .public_key(key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
                    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                    .sign(key, hashes.SHA256()))
            return key, cert

        key, ca = authority("Ephemeral classroom test CA")
        _, unrelated = authority("Unrelated ephemeral test CA")
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
                .issuer_name(ca.subject).public_key(leaf_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
                .sign(key, hashes.SHA256()))
        cls.ca_file, cls.unrelated_file = cls.folder / "ca.pem", cls.folder / "unrelated.pem"
        cls.ca_file.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        cls.unrelated_file.write_bytes(unrelated.public_bytes(serialization.Encoding.PEM))
        cert_file, key_file = cls.folder / "cert.pem", cls.folder / "key.pem"
        cert_file.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        key_file.write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        handler = make_handler(AuthState(load_devices(ROOT / "data" / "demo_devices.json")))
        handler.log_message = lambda *args: None
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_file, key_file)
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.url = f"https://127.0.0.1:{cls.server.server_port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.temp.cleanup()

    def test_trusted_authentication_and_untrusted_rejection(self):
        result = verify(self.url, self.ca_file, self.unrelated_file, ROOT / "data" / "demo_devices.json")
        self.assertTrue(result["trusted_authentication"], result)
        self.assertTrue(result["untrusted_certificate_rejected"], result)
        self.assertFalse(result["errors"])
        self.assertTrue(result["tls_version"].startswith("TLS"))

    def test_using_same_ca_does_not_claim_untrusted_rejection(self):
        result = verify(self.url, self.ca_file, self.ca_file, ROOT / "data" / "demo_devices.json")
        self.assertTrue(result["trusted_authentication"])
        self.assertFalse(result["untrusted_certificate_rejected"])

    def test_cli_writes_importable_evidence(self):
        output = self.folder / "evidence.json"
        completed = subprocess.run([sys.executable, str(ROOT / "verify_tls.py"), "--server", self.url,
                                    "--ca-file", str(self.ca_file), "--untrusted-ca-file", str(self.unrelated_file),
                                    "--output", str(output)], capture_output=True, text=True, timeout=15)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["schema"], "INS-IOT-TLS-CHECK-v1")


if __name__ == "__main__":
    unittest.main()
