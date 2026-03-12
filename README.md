# archiviomd-verify

Standalone verification tool for **ArchivioMD** and **ArchivioID** — two WordPress plugins for cryptographic document signing.

Zero WordPress dependency. Given any published post URL the tool fetches the plugin's public REST endpoint and verifies every cryptographic layer locally, printing a pass/fail result for each one.

---

## Requirements

- **Python 3.8 or later**
- Internet access to the site being verified (and to Rekor / Cloudflare DoH for transparency log and DANE checks)

Check your Python version:

```
python3 --version
```

---

## Installation

### 1. Clone or unzip

Place `archiviomd-verify.py`, `archiviomd-verify.html`, and `requirements.txt` in any directory.

### 2. Install Python dependencies

```
pip install -r requirements.txt
```
Or 
```
pipx install -r requirements.txt
```
Or use the docker file
```
docker pull ghcr.io/mountainviewprovisions/archiviomd-verify:v1.0.4
```

This installs `cryptography`, which enables offline Ed25519, ECDSA P-256, and RSA verification. Everything else is Python stdlib.

For SLH-DSA (post-quantum, NIST FIPS 205) offline verification, also install:

```
pip install pyspx
```

### 3. Install runtime binaries (optional but recommended)

| Binary  | Purpose                                      | Install                                      |
|---------|----------------------------------------------|----------------------------------------------|
| openssl | CMS/PKCS#7 and RFC 3161 timestamp offline verify | `apt install openssl` / `brew install openssl` |
| gpg     | OpenPGP (ArchivioID) offline verify          | `apt install gnupg` / `brew install gnupg` / [Gpg4win](https://gpg4win.org) on Windows |

Run `python3 archiviomd-verify.py --verbose https://example.com/post` to see which binaries are detected.

---

## Usage

### Verify a post

```
python3 archiviomd-verify.py https://example.com/my-signed-post
```

### Verify with an explicit Ed25519 public key

```
python3 archiviomd-verify.py https://example.com/post --pubkey <64-hex-chars>
```

Use this when the public key is not auto-discoverable from the site's `.well-known/` endpoint.

### Inspect a Rekor transparency log entry

```
python3 archiviomd-verify.py --rekor 12345678
```

### Verify an RFC 3161 timestamp file

```
python3 archiviomd-verify.py --tsr response.tsr --tsq request.tsq
```

Provide `--tsa-cert-url` if the TSA certificate is not bundled in your system CA store.

### Check DANE DNS records for a domain

```
python3 archiviomd-verify.py --dane example.com
```

### List all ArchivioID PGP keys registered on a site

```
python3 archiviomd-verify.py --pgp-keys https://example.com
```

### Inspect ArchivioID PGP signatures for a specific post

```
python3 archiviomd-verify.py --pgp-keys https://example.com --pgp-post 42
```

### Verbose mode — show dependency status first

```
python3 archiviomd-verify.py --verbose https://example.com/post
```

### Skip TLS certificate verification (staging / self-signed certs)

```
python3 archiviomd-verify.py --no-verify-ssl https://staging.example.com/post
```

> **Warning:** Only use `--no-verify-ssl` on networks you control. It disables all TLS certificate validation.

---

## What gets checked

| # | Layer | Offline? | Requires |
|---|-------|----------|----------|
| 1 | Content hash (SHA-256/512/etc) | ✓ (non-HMAC) | stdlib |
| 2 | Ed25519 bare + DSSE envelope | ✓ | cryptography |
| 3 | SLH-DSA (NIST FIPS 205) | ✓ | pyspx |
| 4 | ECDSA P-256 DSSE | ✓ | cryptography |
| 5 | RSA PSS / PKCS#1v15 | ✓ | cryptography |
| 6 | CMS / PKCS#7 detached sig | ✓ | openssl binary |
| 7 | JSON-LD / W3C Data Integrity | server-side | — |
| 8 | Rekor transparency log | ✓ (inclusion proof) | internet |
| 9 | RFC 3161 trusted timestamp | ✓ | openssl binary |
| 10 | DANE DNS TXT + TLSA | ✓ | internet (DoH) |
| 11 | OpenPGP (ArchivioID bolt-on) | ✓ (if gpg present) | gpg binary |

---

## Output and exit codes

Each section prints one of:

- `✓` — check passed
- `✗` — check failed
- `⚠` — warning or missing optional dependency
- `·` — informational

**Exit code 0** = all performed checks passed.  
**Exit code 1** = one or more checks failed.

This makes the tool safe to use in CI/CD pipelines:

```yaml
# GitHub Actions example
- name: Verify post integrity
  run: python3 archiviomd-verify.py https://example.com/post
```

```sh
# Shell script example
python3 archiviomd-verify.py https://example.com/post || exit 1
```

---

## Browser verifier

Open `archiviomd-verify.html` in any modern browser. It performs client-side verification using the Web Crypto API and requires no installation. Supports layers 1–10 (Ed25519 DSSE, ECDSA P-256 DSSE, content hash, Rekor, RFC 3161 instructions, DANE, JSON-LD).

Layers that require native binaries (SLH-DSA offline, RSA offline, CMS/PKCS#7, OpenPGP) are noted in the UI with a prompt to use the Python CLI.

---

## Notes on HMAC mode

If the site uses HMAC content hashing, offline verification of the content hash requires the `ARCHIVIOMD_HMAC_KEY` secret, which is never published. The tool will report the server-verified status only.

---

## Verification file format

ArchivioMD attaches a downloadable **verification file** (JSON) to each signed post — typically accessible via a badge or download link on the post. The CLI references this file in several places. Its structure is:

```json
{
  "post_id": 42,
  "verification_data": {
    "content_hash": {
      "algorithm": "sha256",
      "hash": "abcdef..."
    },
    "ed25519": {
      "signature_hex": "...",
      "public_key_url": "https://example.com/.well-known/ed25519-pubkey.txt"
    },
    "rsa": {
      "signature_hex": "...",
      "scheme": "rsa-pss-sha256"
    },
    "cms": {
      "signature_b64": "..."
    },
    "rfc3161": {
      "tsr_url": "https://example.com/wp-content/uploads/archiviomd/42.tsr",
      "tsq_url": "https://example.com/wp-content/uploads/archiviomd/42.tsq"
    }
  }
}
```

When verifying manually with `openssl`:

```sh
# CMS / PKCS#7
echo "<signature_b64 value>" | base64 -d > sig.der
openssl cms -verify -inform DER -in sig.der -content message.bin -noverify

# RSA (PSS)
echo "<signature_hex value>" | xxd -r -p > sig.der
openssl dgst -sha256 -verify rsa-pubkey.pem -signature sig.der message.bin

# RFC 3161
openssl ts -verify -in 42.tsr -queryfile 42.tsq -CAfile /etc/ssl/certs/ca-certificates.crt
```

---

## Reproducible installs and version pinning

`requirements.txt` pins `cryptography` to a tested range (`>=41.0.0,<47`). For CI environments or any situation requiring exact reproducibility, use the lock file instead:

```sh
pip install -r requirements-lock.txt
```

To regenerate the lock file after updating `requirements.txt`:

```sh
pip install -r requirements.txt
pip freeze > requirements-lock.txt
```

For hash-verified installs (maximum supply-chain security), use [pip-tools](https://pip-tools.readthedocs.io/):

```sh
pip install pip-tools
pip-compile --generate-hashes requirements.txt -o requirements-lock.txt
pip install --require-hashes -r requirements-lock.txt
```

---

## RFC 3161 timestamp — what it proves and what it doesn't

When the tool reports a timestamp as **VALID**, it means:

- A trusted third-party TSA (timestamp authority) cryptographically signed a hash of the content at the recorded time
- The content hash existed **before** that timestamp
- The TSA's signature has not been tampered with

It does **not** mean:

- The content itself is authentic or unmodified since then
- The author is who they claim to be
- The content hasn't been replaced (the hash in the TSR must be cross-checked against the content hash above it in the output)

For compliance or legal use, the RFC 3161 timestamp is evidence of **prior existence at a specific time**, not a guarantee of content integrity on its own. Treat it as one layer in a chain — the content hash, the signature, and the timestamp together form the complete proof.

---

## Browser verifier — CORS dependency

The HTML verifier (`archiviomd-verify.html`) makes cross-origin fetch requests to the site being verified. This works when:

- The WordPress site sends permissive `Access-Control-Allow-Origin` CORS headers on its REST endpoints (ArchivioMD enables this by default)
- The HTML file is opened locally (`file://`) or served from an allowed origin

It will fail silently or show a CORS error when:

- A WAF (Cloudflare, Sucuri, Wordfence, etc.) strips CORS headers
- A WordPress security plugin blocks REST API access to unauthenticated requests
- The site is behind HTTP Basic Auth or an IP allowlist

If you see a CORS error, use the Python CLI instead — it runs as a normal HTTP client and is not subject to browser CORS restrictions:

```sh
python3 archiviomd-verify.py https://example.com/post
```

---

## Platform notes

**Windows:** ANSI color output requires Windows 10 version 1903 or later with a modern terminal (Windows Terminal, VS Code terminal). On older systems output renders in plain text without color.

**macOS:** `openssl` installed via Homebrew may shadow the system LibreSSL. Either works for the tool's purposes.

**Linux:** All features work with standard package manager installs.
