#!/usr/bin/env python3
"""Validate or explicitly refresh Android's bundled WebAuthn trust data."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import urllib.request
from datetime import date
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "packages/phone_auth_native/android/trust-snapshots.json"
REFRESH_AFTER_DAYS = 30


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate(name: str, data: bytes) -> None:
    if name == "public_suffix_list":
        text = data.decode("utf-8")
        required = ("// VERSION:", "// ===BEGIN ICANN DOMAINS===", "// ===BEGIN PRIVATE DOMAINS===")
        if len(data) < 100_000 or not all(marker in text for marker in required):
            raise ValueError("Public Suffix List is truncated or malformed")
        return

    document = json.loads(data)
    apps = document.get("apps")
    if not isinstance(apps, list) or len(apps) < 10:
        raise ValueError("privileged browser allowlist is empty or malformed")
    for app in apps:
        info = app.get("info", {})
        if app.get("type") != "android" or not info.get("package_name") or not info.get("signatures"):
            raise ValueError("privileged browser allowlist contains an invalid entry")


def load_manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def check(manifest: dict) -> None:
    today = date.today()
    max_age = manifest["max_age_days"]
    for name, snapshot in manifest["snapshots"].items():
        data = (ROOT / snapshot["path"]).read_bytes()
        validate(name, data)
        if digest(data) != snapshot["sha256"]:
            raise ValueError(f"{name} hash differs from trust-snapshots.json")
        age = (today - date.fromisoformat(snapshot["retrieved"])).days
        if age > max_age:
            raise ValueError(f"{name} snapshot is stale ({age} days; maximum {max_age})")


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "BioAuth trust snapshot updater"})
    with urllib.request.urlopen(request, timeout=30) as response:
        if response.url != url or response.headers.get_content_type() not in {
            "application/json",
            "text/plain",
        }:
            raise ValueError(f"unexpected response for {url}")
        data = response.read(2_000_001)
    if len(data) > 2_000_000:
        raise ValueError(f"snapshot from {url} exceeds 2 MB")
    return data


def atomic_write(path: Path, data: bytes) -> None:
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as output:
        output.write(data)
        temporary = Path(output.name)
    os.replace(temporary, path)


def update(manifest: dict) -> None:
    today = date.today()
    for name, snapshot in manifest["snapshots"].items():
        data = fetch(snapshot["url"])
        validate(name, data)
        path = ROOT / snapshot["path"]
        changed = data != path.read_bytes()
        age = (today - date.fromisoformat(snapshot["retrieved"])).days
        if changed:
            atomic_write(path, data)
        if changed or age >= REFRESH_AFTER_DAYS:
            snapshot["retrieved"] = today.isoformat()
            snapshot["sha256"] = digest(data)
    atomic_write(MANIFEST, (json.dumps(manifest, indent=2) + "\n").encode())
    check(manifest)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--update", action="store_true", help="download and replace reviewed snapshots")
    args = parser.parse_args()
    manifest = load_manifest()
    update(manifest) if args.update else check(manifest)
    print("Android trust snapshots are valid")


if __name__ == "__main__":
    main()
