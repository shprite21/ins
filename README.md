# Secure Authentication for IoT Devices

A small, runnable demonstration of device authentication using a fresh server challenge and an HMAC-SHA-256 proof. It uses only the Python standard library.

## Get it running on a teammate's laptop

Requires Python 3.10 or newer and Git. No third-party Python packages are needed.

```powershell
git clone https://github.com/shprite21/ins.git
cd ins
python server.py
```

Open `http://127.0.0.1:8080/` in a browser. **Run security walkthrough** shows the challenge, HMAC proof, and server response, then sends a replay, a tampered proof, and a request for an unregistered device. Each result shows the HTTP status returned by the server.

The command-line device simulator can also be run from a second terminal:

```powershell
cd ins
python device.py sensor-001
```

The simulator requests a random challenge, then returns a keyed proof that binds the challenge to the device ID and one-time session ID. A successful run prints `"authenticated": true`.

To try another registered demo identity, run `python device.py sensor-002`. An unknown identity receives an authentication failure.

## API

- `POST /challenge` with `{"device_id":"sensor-001"}` returns a random challenge, one-time session ID, and 60-second expiry.
- `POST /authenticate` with `device_id`, `session_id`, and hex `proof` verifies the HMAC and consumes the session whether the proof succeeds or fails.
- `GET /` serves the browser demonstration page; `GET /health` reports whether the server is available.

The proof is HMAC-SHA-256 over the domain label `INS-IOT-AUTH-v1`, device ID, session ID, and challenge, separated as defined in the source. Comparisons use Python's constant-time `hmac.compare_digest`.

## HTTPS option

For a local TLS demonstration, supply a certificate and private key:

```powershell
python server.py --host 127.0.0.1 --port 8443 --tls-cert cert.pem --tls-key key.pem
```

Point the client to the matching `https://` URL. Certificate validation remains enabled by the standard client. Do not expose the HTTP mode beyond localhost; it is provided only for a local classroom demonstration.

## Security scope

This is a teaching prototype, not a production identity or key-management system. The checked-in demo keys are public and intentionally unusable as real credentials. The browser walkthrough uses those public keys so classmates can reproduce the exchange; it does not establish production security. A real system needs unique random per-device keys provisioned through a controlled process, protected device storage or a secure element, TLS with verified certificates, authorization policy, revocation and rotation, rate limiting, persistent replay state if scaled across servers, and audited logging. The JSON demo registry is plain text. The server keeps challenge state in memory, so restart invalidates all active challenges.

See `report/` for the CCA report PDF, source, and institute emblem used in the cover.

