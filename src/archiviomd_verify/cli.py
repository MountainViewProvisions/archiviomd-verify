#!/usr/bin/env python3
"""
archiviomd-verify.py — Standalone ArchivioMD + ArchivioID Verification Tool
============================================================================
Zero WordPress dependency. Verifies every cryptographic layer the
ArchivioMD plugin can produce for a given post URL, plus the OpenPGP
detached-signature layer added by the ArchivioID bolt-on plugin.

Requires Python 3.8 or later.

Supported verification layers:
  ─ ArchivioMD ─────────────────────────────────────────────────────────────
  1.  Content hash  (SHA-256/512/etc, standard or HMAC note)
  2.  Ed25519       bare signature + DSSE envelope
  3.  SLH-DSA       NIST FIPS 205 (pyspx, optional)
  4.  ECDSA P-256   bare DER sig + DSSE envelope (cryptography library)
  5.  RSA           PSS or PKCS#1v15 (cryptography library)
  6.  CMS/PKCS#7    detached DER signature (openssl subprocess)
  7.  JSON-LD       W3C Data Integrity proof (Ed25519 or ECDSA)
  8.  Rekor         Sigstore transparency log + inclusion proof
  9.  RFC 3161      Trusted timestamp (.tsr/.tsq offline)
  10. DANE          DNS TXT + TLSA corroboration records

  ─ ArchivioID bolt-on ─────────────────────────────────────────────────────
  11. OpenPGP       Detached PGP signatures (Ed25519/RSA/ECDSA key types)
                    • Enumerate all registered public keys via REST
                    • Check per-post signature status for each key
                    • Offline verify with gpg binary if available
                    • Key revocation / expiry status
                    • Aggregate threshold-policy status
                    • Proof page URL

Usage:
  python3 archiviomd-verify.py https://example.com/my-post
  python3 archiviomd-verify.py https://example.com/post --pubkey <64-hex>
  python3 archiviomd-verify.py --rekor 12345678
  python3 archiviomd-verify.py --tsr response.tsr --tsq request.tsq
  python3 archiviomd-verify.py --dane example.com
  python3 archiviomd-verify.py --pgp-keys https://example.com
  python3 archiviomd-verify.py --pgp-keys https://example.com --pgp-post 42
  python3 archiviomd-verify.py --verbose https://example.com/post

  Exit code: 0 = all checks passed, 1 = one or more checks failed.

Dependencies:
  Required : (none — stdlib only for basic checks)
  Enhanced : pip install cryptography        (Ed25519, ECDSA, RSA offline)
  Optional : pip install pyspx               (SLH-DSA offline)
  Runtime  : openssl binary                  (CMS, RFC 3161)
  Runtime  : gpg binary                      (OpenPGP offline verify)
"""

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
import urllib.parse
from typing import Optional, Tuple

if sys.version_info < (3, 8):
    sys.exit("archiviomd-verify requires Python 3.8 or later.")

# ─── Color helpers ───────────────────────────────────────────────────────────
# Enable ANSI escape codes on Windows 10+ (no-op on other platforms).
if sys.platform == "win32":
    import ctypes
    try:
        ctypes.windll.kernel32.SetConsoleMode(
            ctypes.windll.kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass
RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
GREEN = "\033[32m"; RED = "\033[31m"; YEL = "\033[33m"; CYAN = "\033[36m"

def ok(m):      print(f"  {GREEN}✓{RESET} {m}")
def fail(m):    print(f"  {RED}✗{RESET} {m}")
def warn(m):    print(f"  {YEL}⚠{RESET} {m}")
def info(m):    print(f"  {CYAN}·{RESET} {m}")
def dim(m):     print(f"  {DIM}{m}{RESET}")
def header(m):  print(f"\n{BOLD}{m}{RESET}")
def section(m): print(f"\n{CYAN}── {m} ──{RESET}")

def _has(pkg):
    try: __import__(pkg); return True
    except ImportError: return False

HAS_CRYPTO  = _has("cryptography")
HAS_PYSPX   = _has("pyspx")

# Set to True via --no-verify-ssl to skip TLS certificate verification.
_SSL_VERIFY = True

def _ssl_ctx():
    import ssl
    if _SSL_VERIFY:
        return ssl.create_default_context()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def http_get(url: str, timeout: int = 20) -> Tuple[int, bytes]:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (compatible; archiviomd-verify/2.1)"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, b""
    except Exception as e:
        msg = str(e)
        if "SSL" in msg or "certificate" in msg.lower():
            msg += " (try --no-verify-ssl for self-signed certs)"
        return 0, msg.encode()

def http_json(url: str) -> Optional[dict]:
    s, b = http_get(url)
    if s != 200 or not b: return None
    try: return json.loads(b)
    except: return None

def http_binary(url: str) -> Optional[bytes]:
    s, b = http_get(url)
    return b if s == 200 and b else None

def build_pae(payload_type: str, payload: bytes) -> bytes:
    pt = payload_type.encode()
    return (b"DSSEv1 " + str(len(pt)).encode() + b" " + pt
            + b" " + str(len(payload)).encode() + b" " + payload)

def _normalize(s: str) -> str:
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join(l.strip() for l in s.split("\n")).strip()

def _strip_html(s: str) -> str:
    return re.sub(r"<[^>]+>", "", s)

def canonical_signing_post(post_id, title, slug, content, date_gmt) -> str:
    """mdsm-ed25519-v1 canonical format shared by Ed25519/SLH-DSA/ECDSA/RSA/CMS/JSON-LD."""
    return "\n".join([
        "mdsm-ed25519-v1", str(post_id),
        _normalize(title), slug.strip(),
        _normalize(_strip_html(content)), date_gmt.strip(),
    ])

def canonical_signing_media(att_id, filename, filesize, mime_type, author_id, date_gmt) -> str:
    return "\n".join([
        "mdsm-ed25519-media-v1", str(att_id), filename,
        str(filesize), mime_type, str(author_id), date_gmt,
    ])

def canonical_content_hash(post_id, author_id, content) -> str:
    """MDSM_Archivio_Post::canonicalize_content format for content hash verification."""
    c = content.replace("\r\n", "\n").replace("\r", "\n")
    c = "\n".join(l.strip() for l in c.split("\n")).strip()
    return f"post_id:{post_id}\nauthor_id:{author_id}\ncontent:\n{c}"

_ALGO_MAP = {
    "sha256":     hashlib.sha256,
    "sha384":     hashlib.sha384,
    "sha512":     hashlib.sha512,
    "sha512-256": lambda d: hashlib.new("sha512_256", d),
    "sha3-256":   hashlib.sha3_256,
    "sha3-512":   hashlib.sha3_512,
    "blake2b":    lambda d: hashlib.blake2b(d),
}

def verify_content_hash(canonical: str, expected_hex: str, algorithm: str) -> bool:
    h = _ALGO_MAP.get(algorithm.lower())
    if not h: return False
    try: return h(canonical.encode()).hexdigest().lower() == expected_hex.lower()
    except: return False

def verify_ed25519_bare(message: str, sig_hex: str, pubkey_hex: str) -> bool:
    if not HAS_CRYPTO: return False
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
        pub.verify(bytes.fromhex(sig_hex), message.encode())
        return True
    except: return False

def verify_ed25519_dsse(envelope: dict, pubkey_hex: str) -> bool:
    if not HAS_CRYPTO: return False
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    try:
        pae = build_pae(envelope.get("payloadType",""),
                        base64.b64decode(envelope.get("payload","")))
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
        for s in envelope.get("signatures", []):
            if s.get("alg","ed25519").lower() != "ed25519": continue
            try:
                pub.verify(base64.b64decode(s.get("sig","")), pae)
                return True
            except InvalidSignature: pass
    except: pass
    return False

_PYSPX_MAP = {
    "slh-dsa-shake-128s": "shake_128s", "slh-dsa-shake-128f": "shake_128f",
    "slh-dsa-shake-192s": "shake_192s", "slh-dsa-shake-192f": "shake_192f",
    "slh-dsa-shake-256s": "shake_256s", "slh-dsa-shake-256f": "shake_256f",
    "slh-dsa-sha2-128s":  "sha2_128s",  "slh-dsa-sha2-128f":  "sha2_128f",
    "slh-dsa-sha2-192s":  "sha2_192s",  "slh-dsa-sha2-192f":  "sha2_192f",
    "slh-dsa-sha2-256s":  "sha2_256s",  "slh-dsa-sha2-256f":  "sha2_256f",
}

def verify_slhdsa(message_bytes: bytes, sig_hex: str, pubkey_hex: str, param: str) -> bool:
    if not HAS_PYSPX: return False
    mod_name = _PYSPX_MAP.get(param.lower())
    if not mod_name: return False
    try:
        mod = __import__(f"pyspx.{mod_name}", fromlist=[mod_name])
        mod.verify(message_bytes, bytes.fromhex(sig_hex), bytes.fromhex(pubkey_hex))
        return True
    except: return False

def verify_ecdsa_bare(message_bytes: bytes, sig_hex: str, cert_pem: str) -> bool:
    if not HAS_CRYPTO: return False
    from cryptography.x509 import load_pem_x509_certificate
    from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidSignature
    try:
        pub = load_pem_x509_certificate(cert_pem.encode()).public_key()
        pub.verify(bytes.fromhex(sig_hex), message_bytes, ECDSA(hashes.SHA256()))
        return True
    except: return False

def verify_ecdsa_dsse(envelope: dict, cert_pem: str) -> bool:
    if not HAS_CRYPTO: return False
    from cryptography.x509 import load_pem_x509_certificate
    from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidSignature
    try:
        pae = build_pae(envelope.get("payloadType",""),
                        base64.b64decode(envelope.get("payload","")))
        pub = load_pem_x509_certificate(cert_pem.encode()).public_key()
        for s in envelope.get("signatures", []):
            if "ecdsa" not in s.get("alg","").lower(): continue
            try:
                pub.verify(base64.b64decode(s.get("sig","")), pae, ECDSA(hashes.SHA256()))
                return True
            except InvalidSignature: pass
    except: pass
    return False

def verify_rsa(message_bytes: bytes, sig_hex: str, pubkey_pem: str,
               scheme: str = "rsa-pss-sha256") -> bool:
    if not HAS_CRYPTO: return False
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding as ap
    from cryptography.exceptions import InvalidSignature
    try:
        pub = serialization.load_pem_public_key(pubkey_pem.encode())
        sig = bytes.fromhex(sig_hex)
        if scheme == "rsa-pss-sha256":
            pub.verify(sig, message_bytes,
                       ap.PSS(mgf=ap.MGF1(hashes.SHA256()),
                               salt_length=ap.PSS.MAX_LENGTH),
                       hashes.SHA256())
        elif scheme == "rsa-pkcs1v15-sha256":
            pub.verify(sig, message_bytes, ap.PKCS1v15(), hashes.SHA256())
        else: return False
        return True
    except: return False

def _openssl_available() -> bool:
    try:
        r = subprocess.run(["openssl","version"], capture_output=True, timeout=5)
        return r.returncode == 0
    except: return False

def _gpg_available() -> bool:
    for binary in ["gpg", "gpg2"]:
        try:
            r = subprocess.run([binary, "--version"], capture_output=True, timeout=5)
            if r.returncode == 0:
                return binary
        except: pass
    return None

def verify_cms(message_bytes: bytes, sig_b64: str) -> Optional[bool]:
    if not _openssl_available(): return None
    with tempfile.TemporaryDirectory() as td:
        sig_f = os.path.join(td, "sig.der")
        msg_f = os.path.join(td, "msg.txt")
        with open(sig_f, "wb") as f: f.write(base64.b64decode(sig_b64))
        with open(msg_f, "wb") as f: f.write(message_bytes)
        try:
            r = subprocess.run(
                ["openssl","cms","-verify","-inform","DER",
                 "-in",sig_f,"-content",msg_f,"-noverify"],
                capture_output=True, timeout=30)
            return r.returncode == 0
        except: return None

def _b64url_decode(s: str) -> bytes:
    pad = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * (pad % 4))

def verify_jsonld_proof(proof: dict, message_bytes: bytes,
                         pubkey_hex: str = "", cert_pem: str = "") -> bool:
    suite = proof.get("cryptosuite","") or proof.get("type","")
    try: sig_bytes = _b64url_decode(proof.get("proofValue",""))
    except: return False

    if "eddsa" in suite.lower():
        if not pubkey_hex or not HAS_CRYPTO: return False
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex)).verify(sig_bytes, message_bytes)
            return True
        except: return False

    if "ecdsa" in suite.lower():
        if not cert_pem or not HAS_CRYPTO: return False
        from cryptography.x509 import load_pem_x509_certificate
        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
        from cryptography.hazmat.primitives import hashes
        from cryptography.exceptions import InvalidSignature
        try:
            pub = load_pem_x509_certificate(cert_pem.encode()).public_key()
            pub.verify(sig_bytes, message_bytes, ECDSA(hashes.SHA256()))
            return True
        except: return False

    return False

def verify_tsr_file(tsr_path: str, tsq_path: Optional[str] = None,
                     ca_url: Optional[str] = None) -> Optional[bool]:
    if not _openssl_available(): return None
    with tempfile.TemporaryDirectory() as td:
        cafile = None
        if ca_url:
            ca_data = http_binary(ca_url)
            if ca_data:
                cafile = os.path.join(td, "tsa.crt")
                open(cafile,"wb").write(ca_data)
        if not cafile:
            for p in ["/etc/ssl/certs/ca-certificates.crt","/etc/ssl/cert.pem",
                      "/usr/local/etc/openssl/cert.pem"]:
                if os.path.exists(p): cafile = p; break

        cmd = ["openssl","ts","-verify","-in",tsr_path]
        if tsq_path: cmd += ["-queryfile", tsq_path]
        if cafile:   cmd += ["-CAfile", cafile]
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=30)
            return r.returncode == 0
        except: return None

def verify_tsr_url(tsr_url: str) -> Optional[bool]:
    with tempfile.TemporaryDirectory() as td:
        tsr_data = http_binary(tsr_url)
        if not tsr_data: return None
        tsr_path = os.path.join(td, "r.tsr")
        open(tsr_path,"wb").write(tsr_data)

        tsq_url = tsr_url.replace(".tsr",".tsq")
        tsq_path = None
        tsq_data = http_binary(tsq_url)
        if tsq_data:
            tsq_path = os.path.join(td, "r.tsq")
            open(tsq_path,"wb").write(tsq_data)

        ca_url = None
        mf_url = tsr_url.replace(".tsr",".manifest.json")
        mf = http_json(mf_url)
        if mf:
            ca_url = (mf.get("tsa_verification") or {}).get("cert_url") or None

        return verify_tsr_file(tsr_path, tsq_path, ca_url)

REKOR_API = "https://rekor.sigstore.dev/api/v1"

def fetch_rekor_entry(log_index: int) -> dict:
    out = {"found":False,"uuid":None,"artifact_hash":None,
           "custom_props":{},"integrated_time":None,"inclusion_proof":False}
    data = http_json(f"{REKOR_API}/log/entries?logIndex={log_index}")
    if not data or not isinstance(data,dict): return out
    out["found"] = True
    uuid  = next(iter(data))
    entry = data[uuid]
    out["uuid"] = uuid
    try:
        body = json.loads(base64.b64decode(entry.get("body","")))
        spec = body.get("spec",{})
        out["artifact_hash"] = spec.get("data",{}).get("hash",{}).get("value")
        out["custom_props"]  = spec.get("customProperties",{})
    except: pass
    out["integrated_time"] = entry.get("integratedTime")
    out["inclusion_proof"] = bool((entry.get("verification") or {}).get("inclusionProof"))
    return out

DOH = "https://cloudflare-dns.com/dns-query"

def _doh(name: str, rtype: str = "TXT") -> Optional[list]:
    url = f"{DOH}?name={urllib.parse.quote(name)}&type={rtype}"
    req = urllib.request.Request(url, headers={"Accept":"application/dns-json",
                                               "User-Agent":"Mozilla/5.0 (compatible; archiviomd-verify/2.1)"})
    try:
        with urllib.request.urlopen(req, timeout=10, context=_ssl_ctx()) as r:
            return [a.get("data","") for a in json.loads(r.read()).get("Answer",[])]
    except: return None

def check_dane(domain: str) -> dict:
    results = {}
    for algo, sub in [("ed25519","_archiviomd._domainkey"),
                      ("slhdsa","_archiviomd-slhdsa._domainkey"),
                      ("ecdsa","_archiviomd-ecdsa._domainkey"),
                      ("rsa","_archiviomd-rsa._domainkey")]:
        name = f"{sub}.{domain}"
        ans  = _doh(name, "TXT")
        if ans is None:     results[algo] = {"status":"error","name":name}
        elif ans:           results[algo] = {"status":"found","name":name,
                                             "value":" ".join(ans).replace('"',"")}
        else:               results[algo] = {"status":"not_found","name":name}

    tlsa_name = f"_443._tcp.{domain}"
    tlsa = _doh(tlsa_name, "TLSA")
    if tlsa is None: results["tlsa"] = {"status":"error","name":tlsa_name}
    elif tlsa:       results["tlsa"] = {"status":"found","name":tlsa_name,"values":tlsa}
    else:            results["tlsa"] = {"status":"not_found","name":tlsa_name}

    disc_url = f"https://{domain}/.well-known/archiviomd-dns.json"
    disc     = http_json(disc_url)
    results["discovery"] = {"url":disc_url,"found":disc is not None,"data":disc}
    return results

def key_fingerprint(hex_key: str) -> str:
    return hashlib.sha256(bytes.fromhex(hex_key)).hexdigest()

def resolve_ed25519_pubkey(data: dict, override: Optional[str]) -> Optional[str]:
    if override: return override
    pk = (data.get("ed25519") or {}).get("pub_key_hex")
    if pk: return pk
    wk = ((data.get("ed25519") or {}).get("public_key_url") or
          (data.get("public_keys") or {}).get("ed25519",{}).get("well_known"))
    if wk:
        _, body = http_get(wk)
        cand = body.decode("utf-8","replace").strip()
        if len(cand)==64 and all(c in "0123456789abcdefABCDEF" for c in cand):
            return cand
    return None

def _archivio_id_api(origin: str, path: str) -> Optional[dict]:
    url = f"{origin}/wp-json/archivio-id/v1{path}"
    return http_json(url)

def fetch_archivio_id_keys(origin: str) -> list:
    data = _archivio_id_api(origin, "/keys")
    if not data: return []
    return data.get("keys", [])

def fetch_archivio_id_post_signatures(origin: str, post_id: int) -> Optional[dict]:
    return _archivio_id_api(origin, f"/posts/{post_id}/signatures")

def gpg_verify_detached(armored_sig: str, signed_data: str,
                         armored_pubkey: str) -> Optional[bool]:
    # Returns True=valid, False=invalid, None=gpg unavailable or error
    gpg_bin = _gpg_available()
    if not gpg_bin: return None
    with tempfile.TemporaryDirectory() as td:
        keyring  = os.path.join(td, "keyring.gpg")
        msg_f    = os.path.join(td, "message.txt")
        sig_f    = os.path.join(td, "sig.asc")
        pubkey_f = os.path.join(td, "pubkey.asc")

        with open(pubkey_f, "w") as f: f.write(armored_pubkey)
        with open(msg_f,    "w") as f: f.write(signed_data)
        with open(sig_f,    "w") as f: f.write(armored_sig)

        base_args = [
            gpg_bin, "--batch", "--no-default-keyring",
            "--keyring", keyring,
        ]
        try:
            imp = subprocess.run(
                base_args + ["--import", pubkey_f],
                capture_output=True, timeout=15
            )
            if imp.returncode != 0:
                return None

            ver = subprocess.run(
                base_args + ["--verify", sig_f, msg_f],
                capture_output=True, timeout=15
            )
            return ver.returncode == 0
        except Exception:
            return None

def _sig_status_badge(status: str) -> str:
    """Return a colored status string for display."""
    s = (status or "").lower()
    if s == "verified":    return f"{GREEN}verified{RESET}"
    if s in ("invalid",):  return f"{RED}invalid{RESET}"
    if s == "uploaded":    return f"{YEL}uploaded (not yet verified){RESET}"
    if s == "error":       return f"{RED}error{RESET}"
    if s == "not_signed":  return f"{DIM}not signed{RESET}"
    return f"{DIM}{status}{RESET}"

def _key_algo_label(algo: str) -> str:
    a = (algo or "").lower()
    if "ed25519" in a or "eddsa" in a: return "Ed25519"
    if "rsa" in a:                     return "RSA"
    if "ecdsa" in a:                   return "ECDSA"
    return algo or "unknown"

def verify_archivio_id(origin: str, post_id: int, archiviomd_data: dict,
                        verbose: bool = False) -> bool:
    section("ArchivioID — OpenPGP Signatures")

    keys_url = f"{origin}/wp-json/archivio-id/v1/keys"
    keys = fetch_archivio_id_keys(origin)

    if keys is None:
        warn("ArchivioID REST endpoint not reachable — plugin may not be active")
        return True

    if not keys:
        info("ArchivioID is active but no public keys are registered on this site")
        return True

    info(f"Registered public keys: {len(keys)}  ({keys_url})")
    for k in keys:
        algo    = _key_algo_label(k.get("algorithm",""))
        fp      = (k.get("fingerprint") or "")[:40]
        label   = k.get("label","")
        expires = k.get("expires_at") or "no expiry"
        key_id  = k.get("key_id","")
        dim(f"  [{algo:8s}] {fp}  \"{label}\"  key_id={key_id}  expires={expires}")

    if not post_id:
        info("No post ID available — cannot check per-post signatures")
        return True

    sigs_url  = f"{origin}/wp-json/archivio-id/v1/posts/{post_id}/signatures"
    post_data = fetch_archivio_id_post_signatures(origin, post_id)

    if post_data is None:
        warn(f"Could not fetch signature records for post {post_id}")
        dim(f"  URL tried: {sigs_url}")
        return True

    sigs      = post_data.get("signatures", [])
    agg       = post_data.get("aggregate_status", "unknown")
    proof_url = post_data.get("proof_url")
    archivio_hash = post_data.get("archivio_hash","")

    if proof_url:
        info(f"Proof page: {proof_url}")
    info(f"Aggregate status: {_sig_status_badge(agg)}")

    if archivio_hash:
        dim(f"  ArchivioMD hash on record: {archivio_hash[:60]}{'…' if len(archivio_hash)>60 else ''}")

    if not sigs:
        info("No OpenPGP signatures have been uploaded for this post")
        return True

    info(f"Signature records: {len(sigs)}")

    gpg_bin   = _gpg_available()
    all_ok    = True
    any_valid = False

    hex_hash = ""
    archiviomd_hash_block = archiviomd_data.get("hash", {})
    if archiviomd_hash_block.get("available"):
        hex_hash = archiviomd_hash_block.get("hash", "")

    for i, sig in enumerate(sigs, 1):
        fp         = (sig.get("key_fingerprint") or "").upper()
        key_label  = sig.get("key_label","")
        algo       = _key_algo_label(sig.get("key_algorithm",""))
        status     = sig.get("status","")
        verified_at = sig.get("verified_at") or ""
        hash_algo  = sig.get("hash_algorithm","")
        key_revoked = sig.get("key_revoked", False)
        failure    = sig.get("failure_reason","")
        sign_method = sig.get("sign_method","upload")

        print(f"\n  {BOLD}[{i}] {fp or 'unknown fingerprint'}{RESET}")
        dim(f"      Label: {key_label}  |  Algo: {algo}  |  Method: {sign_method}")
        dim(f"      Hash algo: {hash_algo}  |  Status: {_sig_status_badge(status)}")
        if verified_at: dim(f"      Verified at: {verified_at}")
        if key_revoked: warn("      Key is REVOKED — this signature cannot be trusted")
        if failure:     warn(f"      Failure reason: {failure}")

        if status == "verified" and not key_revoked:
            ok(f"Server-side PGP verification: VERIFIED (key: {key_label or fp[:20]}…)")
            any_valid = True
        elif status == "invalid" or key_revoked:
            fail(f"Server-side PGP verification: INVALID")
            all_ok = False
        elif status == "uploaded":
            warn(f"Signature uploaded but not yet server-verified")
        else:
            warn(f"Status: {status}")

        if gpg_bin and hex_hash and fp:
            key_db_id = sig.get("key_id")
            sig_asc   = None

            if key_db_id:
                dl_url  = f"{origin}/wp-json/archivio-id/v1/posts/{post_id}/signatures/{key_db_id}/download"
                sc, sb  = http_get(dl_url)
                if sc == 200 and sb and b"BEGIN PGP" in sb:
                    sig_asc = sb.decode("utf-8", "replace")

            if sig_asc:
                armored_key = None
                key_export_url = f"{origin}/wp-json/archivio-id/v1/keys/{key_db_id}/export"
                ks, kb = http_get(key_export_url)
                if ks == 200 and kb and b"BEGIN PGP" in kb:
                    armored_key = kb.decode("utf-8","replace")

                if armored_key and hex_hash:
                    r = gpg_verify_detached(sig_asc, hex_hash, armored_key)
                    if r is True:
                        ok(f"OpenPGP offline ({gpg_bin}): VALID")
                        any_valid = True
                    elif r is False:
                        fail(f"OpenPGP offline ({gpg_bin}): INVALID")
                        all_ok = False
                    else:
                        warn(f"OpenPGP offline: gpg import/verify step failed")
                elif not armored_key:
                    dim(f"      Offline: armored public key not accessible at {key_export_url}")
                    dim(f"      To verify manually:")
                    dim(f"        gpg --verify <sig.asc> <message.txt>")
                    dim(f"        (message.txt = hex hash: {hex_hash[:40]}…)")
            elif key_db_id:
                dim(f"      Offline: .asc download not available at REST (expected {dl_url})")
                if hex_hash:
                    dim(f"      If you have the .asc file, run:")
                    dim(f"        echo -n '{hex_hash}' > msg.txt")
                    dim(f"        gpg --verify sig.asc msg.txt")
        elif not gpg_bin:
            dim(f"      Offline GPG verify: install gpg for offline verification")

    if agg == "verified" or any_valid:
        ok(f"OpenPGP aggregate: {_sig_status_badge(agg)}")
    elif agg in ("invalid", "error"):
        fail(f"OpenPGP aggregate: {_sig_status_badge(agg)}")
        all_ok = False
    else:
        warn(f"OpenPGP aggregate: {_sig_status_badge(agg)}")

    return all_ok

def verify_post(url: str, pubkey_override: Optional[str] = None,
                verbose: bool = False) -> bool:

    print(f"\n{BOLD}ArchivioMD + ArchivioID Verification{RESET}")
    print(f"{DIM}URL: {url}{RESET}")

    origin   = "/".join(url.split("/")[:3])
    rest_url = f"{origin}/wp-json/archiviomd/v1/verify?url={urllib.parse.quote(url)}"
    dim(f"REST: {rest_url}")

    status, body = http_get(rest_url)
    if status != 200 or not body:
        fail(f"REST endpoint returned HTTP {status}"); return False
    try: data = json.loads(body)
    except: fail("Invalid JSON from REST endpoint"); return False

    post_id   = data.get("post_id", 0)
    post_type = data.get("post_type","post")
    features  = (data.get("plugin") or {}).get("features", {})
    canonical = data.get("canonical", {})
    pub_keys  = data.get("public_keys", {})
    anchors   = data.get("anchors", {})

    info(f"Post ID: {post_id}  Type: {post_type}")
    active = [k for k,v in features.items() if v]
    if active: dim(f"Active features: {', '.join(active)}")

    all_ok = True

    section("Content Hash")
    hd = data.get("hash", {})
    if hd.get("available"):
        algo  = hd.get("algorithm","sha256")
        mode  = hd.get("mode","standard")
        hx    = hd.get("hash","")
        hmac  = hd.get("hmac_mode", False)
        srv_v = hd.get("verified", False)

        info(f"Algorithm: {hd.get('algorithm_label', algo)}  Mode: {hd.get('mode_label', mode)}")
        info(f"Hash: {hx[:40]}{'…' if len(hx)>40 else ''}")

        if srv_v: ok("Server-side content hash: VERIFIED")
        else:     fail("Server-side content hash: NOT VERIFIED"); all_ok = False

        if hmac:
            warn("HMAC mode — offline verification requires ARCHIVIOMD_HMAC_KEY secret")
        else:
            c_post_id   = canonical.get("post_id", post_id)
            c_author_id = canonical.get("author_id", 0)
            dim("Offline: canonical = post_id:{id}\\nauthor_id:{author_id}\\ncontent:\\n{stripped}")
            dim(f"         then {algo}(canonical) must equal the hash above")
            dim(f"         post_id={c_post_id}  author_id={c_author_id}")
    else:
        info("Content hash: not available for this post")

    section("Ed25519 Signature")
    ed = data.get("ed25519", {})
    if ed.get("available"):
        sig_hex   = ed.get("signature_hex","")
        dsse_wrap = ed.get("dsse")
        signed_at = ed.get("signed_at","")
        key_id    = ed.get("key_id","")
        srv_v     = ed.get("verified", False)

        info(f"Signed at: {signed_at}")
        if key_id: info(f"Key fingerprint: {key_id}")
        if srv_v: ok("Server-side Ed25519: VERIFIED")
        else:     warn("Server-side Ed25519: not verified")

        pubkey_hex = resolve_ed25519_pubkey(data, pubkey_override)
        if pubkey_hex:
            fp = key_fingerprint(pubkey_hex)
            if key_id and fp.lower() != key_id.lower():
                warn(f"Key-ID mismatch! REST={key_id[:20]}… computed={fp[:20]}…")
            else:
                dim(f"Key-ID matches: {fp[:32]}…")

            if dsse_wrap and dsse_wrap.get("envelope"):
                env = dsse_wrap["envelope"]
                r = verify_ed25519_dsse(env, pubkey_hex)
                if r:   ok("Ed25519 DSSE: VALID (offline)")
                elif not HAS_CRYPTO: warn("Ed25519 DSSE: install cryptography for offline verify")
                else:   fail("Ed25519 DSSE: INVALID"); all_ok = False
            elif sig_hex:
                canonical = canonical_signing_post(
                    post_id,
                    data.get("canonical", {}).get("title", ""),
                    data.get("canonical", {}).get("slug", ""),
                    data.get("canonical", {}).get("content", ""),
                    data.get("canonical", {}).get("date_gmt", ""),
                )
                r = verify_ed25519_bare(canonical, sig_hex, pubkey_hex)
                if r:   ok("Ed25519 bare: VALID (offline)")
                elif not HAS_CRYPTO: warn("Ed25519 bare: install cryptography for offline verify")
                else:   fail("Ed25519 bare: INVALID"); all_ok = False
            else:
                dim("No DSSE envelope on this post (DSSE mode not enabled)")
        else:
            warn("Could not resolve Ed25519 public key")
    else:
        info("Ed25519 not enabled or no signature")

    section("SLH-DSA (Post-Quantum, NIST FIPS 205)")
    slh = data.get("slhdsa", {})
    if slh.get("available"):
        param     = slh.get("param","SLH-DSA-SHA2-128s")
        sig_hex   = slh.get("signature_hex","")
        signed_at = slh.get("signed_at","")
        srv_v     = slh.get("verified", False)

        info(f"Parameter set: {param}")
        info(f"Signed at: {signed_at}")
        if srv_v: ok("Server-side SLH-DSA: VERIFIED")
        else:     warn("Server-side SLH-DSA: not verified")

        pk_url = slh.get("public_key_url") or (pub_keys.get("slhdsa") or {}).get("well_known")
        slh_pk = None
        if pk_url:
            _, pk_body = http_get(pk_url)
            cand = pk_body.decode("utf-8","replace").strip()
            if all(c in "0123456789abcdefABCDEF" for c in cand):
                slh_pk = cand

        msg_bytes = None
        ed_dsse   = (data.get("ed25519") or {}).get("dsse") or {}
        env       = ed_dsse.get("envelope") if ed_dsse else None
        if env:
            try:
                payload = base64.b64decode(env.get("payload",""))
                pae = build_pae(env.get("payloadType",""), payload)
                for s in env.get("signatures",[]):
                    if "slh-dsa" in s.get("alg","").lower():
                        msg_bytes = pae; break
                if msg_bytes is None:
                    msg_bytes = payload
            except: pass

        if slh_pk and sig_hex and msg_bytes and HAS_PYSPX:
            r = verify_slhdsa(msg_bytes, sig_hex, slh_pk, param)
            if r:   ok(f"SLH-DSA ({param}): VALID (offline)")
            else:   fail(f"SLH-DSA ({param}): INVALID"); all_ok = False
        elif not HAS_PYSPX:
            warn("SLH-DSA offline verify: pip install pyspx")
        elif not slh_pk:
            warn(f"SLH-DSA: could not fetch public key from {pk_url}")
        else:
            dim("SLH-DSA: canonical message not available for offline verify")
    else:
        info("SLH-DSA not enabled or no signature")

    section("ECDSA P-256")
    ecdsa = data.get("ecdsa", {})
    if ecdsa.get("available"):
        sig_hex   = ecdsa.get("signature_hex","")
        dsse_env  = ecdsa.get("dsse")
        signed_at = ecdsa.get("signed_at","")
        cert_url  = ecdsa.get("certificate_url","")
        srv_v     = ecdsa.get("verified", False)

        info(f"Algorithm: ecdsa-p256-sha256")
        info(f"Signed at: {signed_at}")
        if cert_url: info(f"Certificate: {cert_url}")
        if srv_v: ok("Server-side ECDSA: VERIFIED")
        else:     warn("Server-side ECDSA: not verified")

        cert_pem = None
        if cert_url:
            _, cert_bytes = http_get(cert_url)
            if cert_bytes and b"CERTIFICATE" in cert_bytes:
                cert_pem = cert_bytes.decode("utf-8","replace")

        if cert_pem:
            if dsse_env and isinstance(dsse_env, dict):
                r = verify_ecdsa_dsse(dsse_env, cert_pem)
                if r:                ok("ECDSA P-256 DSSE: VALID (offline)")
                elif not HAS_CRYPTO: warn("ECDSA: install cryptography for offline verify")
                else:                fail("ECDSA P-256 DSSE: INVALID"); all_ok = False
            elif sig_hex:
                dim("ECDSA bare signature present; canonical message needed for offline verify")
                dim(f"  sig: {sig_hex[:40]}…")
                dim("  openssl dgst -sha256 -verify ecdsa-cert.pem -signature <der> message.bin")
        elif not HAS_CRYPTO:
            warn("ECDSA: install cryptography for offline verify")
        elif cert_url:
            warn(f"ECDSA: certificate not accessible at {cert_url}")
    else:
        info("ECDSA P-256 not enabled or no signature")

    section("RSA Compatibility Signature")
    if features.get("rsa"):
        rsa_wk = f"{origin}/.well-known/rsa-pubkey.pem"
        info(f"RSA signing enabled  |  Public key: {rsa_wk}")
        _, rsa_bytes = http_get(rsa_wk)
        if rsa_bytes and b"PUBLIC KEY" in rsa_bytes:
            ok("RSA public key is accessible at /.well-known/rsa-pubkey.pem")
            rsa_pem = rsa_bytes.decode("utf-8","replace")
            dim(f"  Key size: {len(rsa_pem)} bytes PEM")
        else:
            warn("RSA public key not accessible at /.well-known/rsa-pubkey.pem")
        dim("RSA sig in the ArchivioMD verification file (JSON download attached to the post). Offline:")
        dim("  Fields: verification_data.rsa.signature_hex → decode hex → sig.der")
        dim("  openssl dgst -sha256 -verify rsa-pubkey.pem -signature sig.der message.bin")
        dim("  (scheme: rsa-pss-sha256 or rsa-pkcs1v15-sha256 — check verification_data.rsa.scheme)")
    else:
        info("RSA not enabled on this site")

    section("CMS / PKCS#7 Detached Signature (RFC 5652)")
    if features.get("cms"):
        info("CMS/PKCS#7 signing enabled")
        has_ossl = _openssl_available()
        cms_data = data.get("cms", {})
        sig_b64  = cms_data.get("signature_b64", "")
        msg_hex  = cms_data.get("signed_content_hex", "")
        srv_v    = cms_data.get("verified", False)

        if srv_v: ok("Server-side CMS: VERIFIED")
        else:     warn("Server-side CMS: not reported as verified")

        if has_ossl and sig_b64 and msg_hex:
            try:
                msg_bytes = bytes.fromhex(msg_hex)
                r = verify_cms(msg_bytes, sig_b64)
                if r is True:    ok("CMS/PKCS#7 offline (openssl): VALID")
                elif r is False: fail("CMS/PKCS#7 offline (openssl): INVALID"); all_ok = False
                else:            warn("CMS offline: openssl returned unexpected result")
            except Exception as exc:
                warn(f"CMS offline: could not run verify ({exc})")
        elif has_ossl:
            info("OpenSSL available — CMS signatures in the ArchivioMD verification file can be verified:")
            dim("  The verification file is a JSON download attached to the post.")
            dim("  Fields: verification_data.cms.signature_b64 → base64 decode → sig.der")
            dim("  base64 -d sig.b64 > sig.der")
            dim("  openssl cms -verify -inform DER -in sig.der -content msg.txt -noverify")
        else:
            warn("OpenSSL not found — install it for CMS verification")
        dim("Key source: ECDSA P-256 cert (primary) or RSA (fallback)")
    else:
        info("CMS/PKCS#7 not enabled on this site")

    section("JSON-LD / W3C Data Integrity")
    if features.get("jsonld"):
        did_url = f"{origin}/.well-known/did.json"
        info(f"JSON-LD active  |  DID document: {did_url}")
        did_doc = http_json(did_url)
        if did_doc:
            ok(f"DID document accessible")
            methods = did_doc.get("verificationMethod", [])
            for m in methods[:4]:
                dim(f"  {m.get('id','?')} [{m.get('type','?')}]")
        else:
            warn(f"DID document not accessible at {did_url}")
        dim("JSON-LD proofs available in the ArchivioMD verification file (JSON download) and the per-post JSON-LD endpoint (?format=json-ld)")
        dim("Verify with: jsonld-signatures library or any W3C Data Integrity implementation")
        dim("Suites: eddsa-rdfc-2022 (Ed25519) and/or ecdsa-rdfc-2019 (ECDSA P-256)")
    else:
        info("JSON-LD / W3C Data Integrity not enabled on this site")

    section("Rekor Transparency Log (Sigstore)")
    rekor = anchors.get("rekor", {})
    if rekor.get("available"):
        log_idx = rekor.get("log_index")
        info(f"Log index:   {log_idx}")
        info(f"Anchored at: {rekor.get('anchored_at','')}")
        info(f"Lookup:      {rekor.get('lookup_url','')}")

        if log_idx is not None:
            entry = fetch_rekor_entry(log_idx)
            if entry["found"]:
                ok("Rekor entry found in transparency log")
                if entry["artifact_hash"]:
                    info(f"Artifact hash: {entry['artifact_hash']}")
                if entry["integrated_time"]:
                    import datetime
                    t = datetime.datetime.utcfromtimestamp(entry["integrated_time"])
                    info(f"Integrated:    {t.strftime('%Y-%m-%d %H:%M:%S')} UTC")
                if entry["inclusion_proof"]:
                    ok("Inclusion proof present")
                else:
                    warn("Inclusion proof absent from entry")
                cp = entry.get("custom_props",{})
                if cp.get("archiviomd.site_url"):
                    dim(f"  site_url: {cp['archiviomd.site_url']}")
                if cp.get("archiviomd.pubkey_fingerprint"):
                    fp = cp["archiviomd.pubkey_fingerprint"]
                    dim(f"  pubkey_fingerprint: {fp[:40]}…")
                    pub = resolve_ed25519_pubkey(data, pubkey_override)
                    if pub:
                        expected_fp = key_fingerprint(pub)
                        if fp == expected_fp: ok("Rekor pubkey_fingerprint matches site Ed25519 key")
                        elif fp != "ephemeral": warn("Rekor pubkey_fingerprint does not match known public key")
            else:
                fail(f"Could not fetch Rekor entry {log_idx}")
                all_ok = False
    else:
        info("No Rekor anchor for this post")

    section("RFC 3161 Trusted Timestamp")
    rfc = anchors.get("rfc3161", {})
    if rfc.get("available"):
        tsr_url = rfc.get("tsr_url","")
        anchored_at = rfc.get("anchored_at","")
        info(f"TSR URL:     {tsr_url}")
        info(f"Anchored at: {anchored_at}")
        if tsr_url:
            r = verify_tsr_url(tsr_url)
            if r is True:
                ok("RFC 3161 timestamp: VALID (openssl ts -verify)")
                if anchored_at:
                    ok(f"Provenance: the content hash existed before {anchored_at} (per TSA assertion)")
                    dim("  This proves the content was committed to the TSA before that time,")
                    dim("  NOT that the content is authentic or unmodified since then.")
                    dim("  Cross-check the hash in the TSR against the content hash above.")
            elif r is False:
                fail("RFC 3161 timestamp: INVALID"); all_ok = False
            else:
                warn("RFC 3161: openssl not available or download failed")
        dim("Companion files: swap .tsr → .tsq and .manifest.json")
        dim("Manifest contains the hash algorithm, imprint method, and verify command")
    else:
        info("No RFC 3161 timestamp for this post")

    section("DANE DNS Corroboration")
    if features.get("dane"):
        domain = urllib.parse.urlparse(url).hostname or ""
        info(f"Domain: {domain}")
        dns = check_dane(domain)
        for algo in ["ed25519","slhdsa","ecdsa","rsa"]:
            r = dns.get(algo,{})
            if r.get("status")=="found":
                ok(f"TXT [{algo:8s}] {r['name']}")
                dim(f"    {r.get('value','')[:90]}")
            elif r.get("status")=="not_found":
                dim(f"  TXT [{algo:8s}] not published — {r['name']}")
            else:
                warn(f"  TXT [{algo:8s}] DNS lookup error")
        tlsa = dns.get("tlsa",{})
        if tlsa.get("status")=="found":
            ok(f"TLSA {tlsa.get('name','')}")
            for v in (tlsa.get("values") or [])[:3]: dim(f"    {v}")
        elif tlsa.get("status")=="not_found":
            dim(f"  TLSA: not published")
        else: warn("  TLSA: DNS lookup error")
        disc = dns.get("discovery",{})
        if disc.get("found"): ok(f"Discovery JSON: {disc['url']}")
        else: dim(f"  Discovery JSON: not accessible")
    else:
        info("DANE corroboration not enabled on this site")

    id_ok = verify_archivio_id(origin, post_id, data, verbose)
    if not id_ok:
        all_ok = False

    header("Summary")
    if all_ok: print(f"  {GREEN}{BOLD}All performed checks passed.{RESET}")
    else:      print(f"  {RED}{BOLD}One or more checks FAILED.{RESET}")
    return all_ok

def cmd_rekor(log_index: int):
    section(f"Rekor Entry — Index {log_index}")
    e = fetch_rekor_entry(log_index)
    if not e["found"]: fail(f"Entry not found at index {log_index}"); return
    ok(f"UUID: {e['uuid'][:40]}…")
    if e["artifact_hash"]: info(f"Artifact hash: {e['artifact_hash']}")
    if e["integrated_time"]:
        import datetime
        t = datetime.datetime.utcfromtimestamp(e["integrated_time"])
        info(f"Integrated:   {t.strftime('%Y-%m-%d %H:%M:%S')} UTC")
    if e["inclusion_proof"]: ok("Inclusion proof present")
    else: warn("No inclusion proof")
    props = e.get("custom_props",{})
    if props:
        info("Custom properties:")
        for k,v in props.items(): dim(f"  {k}: {v}")
    print(f"\n  {DIM}https://search.sigstore.dev/?logIndex={log_index}{RESET}")

def cmd_tsr(tsr_path: str, tsq_path: Optional[str] = None, ca_url: Optional[str] = None):
    section("RFC 3161 TSR Verification")
    if not os.path.exists(tsr_path): fail(f"File not found: {tsr_path}"); return
    info(f"TSR: {tsr_path}")
    if tsq_path: info(f"TSQ: {tsq_path}")
    r = verify_tsr_file(tsr_path, tsq_path, ca_url)
    if r is True:
        ok("VALID (openssl ts -verify)")
        ok("Provenance: the hashed content existed before the TSA-asserted timestamp")
        dim("  This proves the data was submitted to the TSA before that time.")
        dim("  It does NOT prove the content is authentic — verify the hash separately.")
    elif r is False:
        fail("INVALID — TSR signature or hash does not verify")
    else:
        warn("openssl not available — install OpenSSL, then:")
        info(f"  openssl ts -verify -in {tsr_path}" +
             (f" -queryfile {tsq_path}" if tsq_path else "") +
             " -CAfile /etc/ssl/certs/ca-certificates.crt")

def cmd_dane(domain: str):
    section(f"DANE DNS Records — {domain}")
    dns = check_dane(domain)
    for algo in ["ed25519","slhdsa","ecdsa","rsa"]:
        r = dns.get(algo,{})
        if r.get("status")=="found":
            ok(f"TXT [{algo}]"); print(f"     {r.get('value','')}")
        elif r.get("status")=="not_found":
            dim(f"  TXT [{algo}]: not published — {r['name']}")
        else: warn(f"  TXT [{algo}]: DNS lookup error")
    tlsa = dns.get("tlsa",{})
    if tlsa.get("status")=="found":
        ok(f"TLSA: {tlsa.get('name','')}")
        for v in tlsa.get("values",[]): dim(f"    {v}")
    else: dim("  TLSA: not published")
    disc = dns.get("discovery",{})
    if disc.get("found"):
        ok(f"Discovery JSON: {disc['url']}")
        recs = (disc.get("data") or {}).get("records",[])
        dim(f"  {len(recs)} record(s)")
    else: dim(f"  Discovery JSON: not accessible at {disc['url']}")

def cmd_pgp_keys(origin: str):
    section(f"ArchivioID Public Keys — {origin}")
    keys = fetch_archivio_id_keys(origin)
    if not keys:
        warn("No keys found or ArchivioID not active")
        return
    info(f"{len(keys)} active key(s):")
    for k in keys:
        algo    = _key_algo_label(k.get("algorithm",""))
        fp      = (k.get("fingerprint") or "").upper()
        label   = k.get("label","")
        expires = k.get("expires_at") or "no expiry"
        key_id  = k.get("key_id","")
        added   = k.get("added","")
        print(f"\n  {BOLD}{fp}{RESET}")
        dim(f"    Label:     {label}")
        dim(f"    Algorithm: {algo}  |  Key-ID: {key_id}")
        dim(f"    Expires:   {expires}  |  Added: {added}")

def cmd_pgp_post(post_id: int, origin: str):
    section(f"ArchivioID Signatures — Post {post_id} on {origin}")
    data = fetch_archivio_id_post_signatures(origin, post_id)
    if not data:
        fail(f"No data returned for post {post_id} — check post ID and origin")
        return
    agg       = data.get("aggregate_status","unknown")
    proof_url = data.get("proof_url")
    sigs      = data.get("signatures",[])

    info(f"Aggregate status: {_sig_status_badge(agg)}")
    if proof_url: info(f"Proof page: {proof_url}")
    info(f"Signatures: {len(sigs)}")

    for i, sig in enumerate(sigs, 1):
        fp      = (sig.get("key_fingerprint") or "").upper()
        status  = sig.get("status","")
        algo    = _key_algo_label(sig.get("key_algorithm",""))
        label   = sig.get("key_label","")
        revoked = sig.get("key_revoked", False)
        failure = sig.get("failure_reason","")
        print(f"\n  [{i}] {fp or 'unknown'}  {_sig_status_badge(status)}")
        dim(f"       {label}  [{algo}]  method={sig.get('sign_method','')}")
        if revoked: warn("       KEY REVOKED")
        if failure: warn(f"       {failure}")

def main():
    p = argparse.ArgumentParser(
        description="ArchivioMD + ArchivioID standalone verifier",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    p.add_argument("url", nargs="?", help="Post URL to verify")
    p.add_argument("--pubkey",       help="Override Ed25519 public key (64 hex chars)")
    p.add_argument("--rekor",        type=int, metavar="LOG_INDEX")
    p.add_argument("--tsr",          metavar="FILE")
    p.add_argument("--tsq",          metavar="FILE")
    p.add_argument("--tsa-cert-url", metavar="URL")
    p.add_argument("--dane",         metavar="DOMAIN")
    p.add_argument("--pgp-keys",     metavar="ORIGIN",
                   help="List ArchivioID public keys for a site (e.g. https://example.com)")
    p.add_argument("--pgp-post",     type=int, metavar="POST_ID",
                   help="Inspect ArchivioID signatures for a specific post ID "
                        "(requires --pgp-keys or a URL from which origin is derived)")
    p.add_argument("--no-verify-ssl", action="store_true",
                   help="Skip TLS certificate verification (for self-signed / staging certs)")
    p.add_argument("--verbose","-v", action="store_true")
    args = p.parse_args()

    global _SSL_VERIFY
    if args.no_verify_ssl:
        _SSL_VERIFY = False
        warn("TLS certificate verification DISABLED — use only on trusted networks")

    if args.verbose:
        header("Dependencies")
        ok("cryptography") if HAS_CRYPTO else warn("cryptography not installed (pip install cryptography)")
        ok("pyspx (SLH-DSA)") if HAS_PYSPX else warn("pyspx not installed (pip install pyspx)")
        gpg = _gpg_available()
        if gpg:
            r = subprocess.run([gpg,"--version"],capture_output=True)
            ok(r.stdout.decode().split("\n")[0].strip())
        else: warn("gpg binary not found (install gnupg for offline PGP verify)")
        if _openssl_available():
            r = subprocess.run(["openssl","version"],capture_output=True)
            ok(r.stdout.decode().strip())
        else: warn("openssl binary not found")

    result = True
    if args.rekor is not None: cmd_rekor(args.rekor)
    elif args.tsr:             cmd_tsr(args.tsr, args.tsq, args.tsa_cert_url)
    elif args.dane:            cmd_dane(args.dane)
    elif args.pgp_keys and args.pgp_post is not None:
        cmd_pgp_post(args.pgp_post, args.pgp_keys.rstrip("/"))
    elif args.pgp_keys:
        cmd_pgp_keys(args.pgp_keys.rstrip("/"))
    elif args.pgp_post and args.url:
        origin = "/".join(args.url.split("/")[:3])
        cmd_pgp_post(args.pgp_post, origin)
    elif args.url:
        result = verify_post(args.url, args.pubkey, args.verbose)
    else:
        p.print_help(); sys.exit(1)

    sys.exit(0 if result else 1)

if __name__ == "__main__":
    main()
