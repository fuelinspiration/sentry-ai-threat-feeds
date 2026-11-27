#!/usr/bin/env python3
"""
Builds a gzipped Android signature delta (delta_v{N}.json.gz) from live
open-source threat feeds:
1. ESET Malware IOCs (unauthenticated GitHub raw .sha256 feeds — works out of the box)
2. Optional MalwareBazaar v2 export (when ABUSECH_AUTH_KEY secret is set)

Signs delta_v{N}.json.gz with the Ed25519 private key and writes manifest.json.
"""
import base64
import gzip
import json
import os
import pathlib
import re
import urllib.request
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

OUT_DIR = pathlib.Path(__file__).resolve().parent / "out"
OUT_DIR.mkdir(parents=True, exist_ok=True)

ESET_TREE_URL = "https://api.github.com/repos/eset/malware-ioc/git/trees/master?recursive=1"
ESET_RAW_BASE = "https://raw.githubusercontent.com/eset/malware-ioc/master/"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def http_get_text(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "SentryAI-ThreatFeed-ETL/1.0"})
    with urllib.request.urlopen(req, timeout=25) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def fetch_eset_ioc_hashes(max_files: int = 25, max_hashes: int = 2000) -> list[dict]:
    additions: list[dict] = []
    seen: set[str] = set()
    try:
        tree_data = json.loads(http_get_text(ESET_TREE_URL))
        sha_paths = [
            item["path"]
            for item in tree_data.get("tree", [])
            if item.get("path", "").endswith(".sha256")
        ]
        # Prioritize mobile/android IOC lists first, then newest malware families
        sha_paths.sort(key=lambda p: (0 if "android" in p.lower() else 1, p))

        for path in sha_paths[:max_files]:
            family = path.split("/")[0]
            try:
                content = http_get_text(ESET_RAW_BASE + path)
            except Exception as exc:
                print(f"Skipping {path}: {exc}")
                continue

            for line in content.splitlines():
                token = line.strip().split()[0].lower() if line.strip() else ""
                if SHA256_RE.match(token) and token not in seen:
                    seen.add(token)
                    additions.append(
                        {
                            "sha256": token,
                            "threat_name": f"ESET.{family}",
                            "category": "Spyware" if "spy" in family.lower() else "Trojan",
                            "severity": 4,
                            "source": "ESET-IOC",
                        }
                    )
                    if len(additions) >= max_hashes:
                        return additions
    except Exception as exc:
        print(f"ESET feed fetch warning: {exc}")
    return additions


def fetch_malwarebazaar_v2(auth_key: str, limit: int = 1000) -> list[dict]:
    if not auth_key:
        return []
    url = f"https://mb-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv"
    additions: list[dict] = []
    try:
        text = http_get_text(url)
        for line in text.splitlines():
            if not line or line.startswith("#"):
                continue
            parts = [p.strip().strip('"') for p in line.split(",")]
            if len(parts) >= 9:
                sha = parts[1].lower()
                sig_name = parts[8] or "Android.Malware.Bazaar"
                if SHA256_RE.match(sha):
                    additions.append(
                        {
                            "sha256": sha,
                            "threat_name": sig_name[:120],
                            "category": "Trojan",
                            "severity": 4,
                            "source": "MalwareBazaar",
                        }
                    )
                    if len(additions) >= limit:
                        break
    except Exception as exc:
        print(f"MalwareBazaar v2 warning: {exc}")
    return additions


def main() -> None:
    db_version = int(os.environ.get("DB_VERSION", "1"))
    repo = os.environ.get("GITHUB_REPOSITORY", "fuelinspiration/sentry-ai-threat-feeds")
    pem_data = os.environ["SIGNING_PRIVATE_KEY_PEM"].strip().encode("utf-8")
    abuse_auth = os.environ.get("ABUSECH_AUTH_KEY", "").strip()

    private_key = load_pem_private_key(pem_data, password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("SIGNING_PRIVATE_KEY must be an Ed25519 private key")

    combined: dict[str, dict] = {
        EICAR_SHA256: {
            "sha256": EICAR_SHA256,
            "threat_name": "EICAR-Standard-AntiVirus-Test-File",
            "category": "TestFile",
            "severity": 1,
            "source": "EICAR",
        }
    }
    for item in fetch_eset_ioc_hashes() + fetch_malwarebazaar_v2(abuse_auth):
        combined[item["sha256"]] = item

    additions = list(combined.values())
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
