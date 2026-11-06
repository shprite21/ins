# Secure Authentication for IoT Devices

A small, runnable demonstration of device authentication using a fresh server challenge and an HMAC-SHA-256 proof. It uses only the Python standard library.

## Get it running on a teammate's laptop

Requires Python 3.10 or newer and Git. No third-party Python packages are needed.

```powershell
git clone https://github.com/shprite21/ins.git
cd ins
python server.py
```

Open `http://127.0.0.1:8080/` in a browser. The dashboard maps every technical section of the CCA report to an explanation or test. **Run authentication** uses the selected sample device. **Run security walkthrough** runs ST-1-4 and ST-6 with sensor-001, including retrying a valid proof after a failed attempt, plus freshness and device/session/challenge-binding probes. Each record shows the actual request and server response, with no secret key field in authentication requests.

**Run ST-5 expiry test** waits about 62 seconds against the unchanged 60-second server TTL. It can be cancelled without recording a pass. **Download evidence** exports timestamped requests, responses, and test statuses as JSON. Results are held only in the current page session and reset on reload. The dashboard explains architecture, exact HMAC bytes, assumptions, key management, setup, applications, future work, and the report references. `/report` opens the original project PDF.

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
- `GET /demo/info` returns public registry IDs, protocol constants, and observed transport/TLS version. It never returns registry keys.
- `GET /report` serves the accompanying CCA PDF.

The proof is HMAC-SHA-256 over the domain label `INS-IOT-AUTH-v1`, device ID, session ID, and challenge, separated as defined in the source. Comparisons use Python's constant-time `hmac.compare_digest`.

## HTTPS option

For a local TLS demonstration, supply a certificate and private key:

```powershell
python server.py --host 127.0.0.1 --port 8443 --tls-cert cert.pem --tls-key key.pem
```

Point the client to the matching `https://` URL. Certificate validation remains enabled by the standard client. Do not expose the HTTP mode beyond localhost; it is provided only for a local classroom demonstration.

For report test ST-7, use a certificate with the correct Subject Alternative Name and a trusted issuing CA. The standard-library verifier checks successful authenticated TLS and rejection when only an unrelated CA is trusted, without changing OS trust:

```powershell
python verify_tls.py --server https://127.0.0.1:8443 --ca-file local-ca.pem --untrusted-ca-file unrelated-ca.pem --output tls-evidence.json
```

Check that the command exits successfully and both booleans in the JSON are true. Import that JSON in the dashboard's **Setup & TLS** section to record an **External PASS**, labelled with the tested HTTPS origin and timestamp. The import is a user-supplied observation, not independent attestation. HTTPS metadata alone never passes ST-7. Do not bypass certificate warnings or disable verification. Certificate issuance and OS trust configuration remain outside scope. Keep private keys out of version control.

## Regression checks

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

These checks cover backend acceptance/rejection, concurrent single-use verification, expiry, malformed bytes, and metadata. The three optional TLS checks create temporary certificates using the development-only `cryptography` package; they are skipped when it is unavailable. No test changes OS trust. The dashboard additionally provides the real-time ST-5 demonstration.

Optional browser regression checks require Playwright and installed Google Chrome in the development environment:

```powershell
node tests/dashboard.cjs
```

The full browser check includes the real expiry wait, mobile layout, evidence downloads, TLS imports, and error handling. `node tests/dashboard.cjs --tls-import-only` checks imports without the expiry wait. Set `IOT_TEST_PYTHON` if the Python executable is not named `python`. The application itself has no third-party runtime dependencies.

## Security scope

This is a teaching prototype, not a production identity or key-management system. The checked-in demo keys are public and intentionally unusable as real credentials. The browser walkthrough uses those public keys so classmates can reproduce the exchange; it does not establish production security. A real system needs unique random per-device keys provisioned through a controlled process, protected device storage or a secure element, TLS with verified certificates, authorization policy, revocation and rotation, rate limiting, persistent replay state if scaled across servers, and audited logging. The JSON demo registry is plain text. The server keeps challenge state in memory, so restart invalidates all active challenges.

See `report/` for the CCA report PDF, source, and institute emblem used in the cover.
