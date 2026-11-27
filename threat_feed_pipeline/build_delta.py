#!/usr/bin/env python3
"""
Builds a gzipped Android signature delta (delta_v{N}.json.gz) from free
open-source threat feeds (MalwareBazaar Android exports), signs it with an
Ed25519 private key, and writes manifest.json for GitHub Releases.
"""
import base64
import gzip
import io
import json
import os
import pathlib
import urllib.request
import zipfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

OUT_DIR = pathlib.Path(__file__).resolve().parent / "out"
OUT_DIR.mkdir(parents=True, exist_ok=True)

MALWAREBAZAAR_RECENT_ZIP = "https://bazaar.abuse.ch/export/txt/sha256/recent/"


def fetch_malwarebazaar_android_hashes(limit: int = 2000) -> list[dict]:
    req = urllib.request.Request(
        MALWAREBAZAAR_RECENT_ZIP,
        headers={"User-Agent": "SentryAI-ThreatFeed-ETL/1.0"},
    )
    additions = []
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read()

    if raw[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            lines = zf.read(zf.namelist()[0]).decode("utf-8", errors="ignore").splitlines()
    else:
        lines = raw.decode("utf-8", errors="ignore").splitlines()

    for line in lines:
        line = line.strip().lower()
        if not line or line.startswith("#") or len(line) != 64:
            continue
        additions.append(
            {
                "sha256": line,
                "threat_name": "Android.Malware.Bazaar",
                "category": "Trojan",
                "severity": 4,
                "source": "MalwareBazaar",
            }
        )
        if len(additions) >= limit:
            break
    return additions


def main() -> None:
    db_version = int(os.environ.get("DB_VERSION", "1"))
    repo = os.environ.get("GITHUB_REPOSITORY", "fuelinspiration/sentry-ai-threat-feeds")
    pem_data = os.environ["SIGNING_PRIVATE_KEY_PEM"].encode("utf-8")

    private_key = load_pem_private_key(pem_data, password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("SIGNING_PRIVATE_KEY must be an Ed25519 private key")

    additions = fetch_malwarebazaar_android_hashes()
    delta_payload = {
        "db_version": db_version,
        "additions": additions,
        "revocations": [],
    }

    delta_filename = f"delta_v{db_version}.json.gz"
    delta_path = OUT_DIR / delta_filename
    compressed_bytes = gzip.compress(json.dumps(delta_payload, separators=(",", ":")).encode("utf-8"))
    delta_path.write_bytes(compressed_bytes)

    sig_b64 = base64.b64encode(private_key.sign(compressed_bytes)).decode("ascii")
    manifest = {
        "latest_version": db_version,
        "delta_url": f"https://github.com/{repo}/releases/download/v{db_version}/{delta_filename}",
        "ed25519_sig": sig_b64,
    }
    (OUT_DIR / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Built {delta_filename} ({len(additions)} signatures, {len(compressed_bytes)} bytes)")


if __name__ == "__main__":
    main()
