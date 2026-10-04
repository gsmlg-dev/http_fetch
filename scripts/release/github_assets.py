"""Create or complete a GitHub release without replacing differing assets."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from hex_packages import PACKAGES


def existing_release(repository, tag):
    token = os.environ["GH_TOKEN"]
    url = f"https://api.github.com/repos/{repository}/releases/tags/{tag}"
    request = Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"})
    try:
        with urlopen(request, timeout=20) as response:
            return json.load(response)
    except HTTPError as error:
        if error.code == 404:
            return None
        raise RuntimeError(f"GitHub release lookup failed: HTTP {error.code}") from error


def run(mode, version, archive_dir):
    if mode not in ("preflight", "complete"):
        raise ValueError("expected preflight or complete")
    if not re.fullmatch(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)", version):
        raise ValueError("stable release version required")
    repository = os.environ["GITHUB_REPOSITORY"]
    tag = f"v{version}"
    archives = [archive_dir / f"{package}-{version}.tar" for package in PACKAGES]
    if any(not archive.is_file() for archive in archives):
        raise RuntimeError("one or more release archives are missing")
    release = existing_release(repository, tag)
    if release is None:
        if mode == "preflight":
            return
        subprocess.run(
            ["gh", "release", "create", tag, *(str(path) for path in archives),
             "--verify-tag", "--title", tag, "--generate-notes",
             "--notes", "Published to Hex.pm: " + ", ".join(
                 f"https://hex.pm/packages/{package}/{version}" for package in PACKAGES)],
            check=True,
        )
        verify_assets(repository, tag, archives)
        return

    assets = {asset["name"]: asset for asset in release["assets"]}
    missing = []
    # Check every existing asset before uploading any missing one.
    with tempfile.TemporaryDirectory() as directory:
        for archive in archives:
            if archive.name not in assets:
                missing.append(archive)
                continue
            subprocess.run(
                ["gh", "release", "download", tag, "--pattern", archive.name, "--dir", directory],
                check=True,
            )
            downloaded = Path(directory) / archive.name
            if hashlib.sha256(downloaded.read_bytes()).digest() != hashlib.sha256(archive.read_bytes()).digest():
                raise RuntimeError(f"GitHub release asset {archive.name} differs from release archive")

    if mode == "complete" and missing:
        subprocess.run(["gh", "release", "upload", tag, *(str(path) for path in missing)], check=True)
    if mode == "complete":
        verify_assets(repository, tag, archives)


def verify_assets(repository, tag, archives):
    release = existing_release(repository, tag)
    if release is None:
        raise RuntimeError("GitHub release missing after completion")
    assets = {asset["name"]: asset for asset in release["assets"]}
    with tempfile.TemporaryDirectory() as directory:
        for archive in archives:
            if archive.name not in assets:
                raise RuntimeError(f"GitHub release asset missing after completion: {archive.name}")
            subprocess.run(["gh", "release", "download", tag, "--pattern", archive.name, "--dir", directory], check=True)
            downloaded = Path(directory) / archive.name
            if hashlib.sha256(downloaded.read_bytes()).digest() != hashlib.sha256(archive.read_bytes()).digest():
                raise RuntimeError(f"GitHub release asset {archive.name} differs from release archive")


if __name__ == "__main__":
    try:
        if len(sys.argv) != 4:
            raise ValueError("usage: github_assets.py preflight|complete VERSION ARCHIVE_DIR")
        run(sys.argv[1], sys.argv[2], Path(sys.argv[3]))
    except (KeyError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
