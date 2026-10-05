"""Build portable Hex archives from the nine umbrella package sources."""

import argparse
import hashlib
from pathlib import Path
import re
import shutil
import subprocess

PACKAGES = (
    "ex_ssl", "elixir_quic", "http_core", "elixir_quic_http3", "http_runtime",
    "http_fetch", "http_web_socket", "http_event_source", "http_web_transport",
)
ROOT = Path(__file__).resolve().parents[2]
WORKSPACE_OPTIONS = ("build_path", "config_path", "deps_path", "lockfile")


def portable_manifest(text):
    for option in WORKSPACE_OPTIONS:
        text = re.sub(rf"(?m)^\s*{option}: \"\.\./\.\./[^\"]+\",\n", "\n", text)
    text = text.replace("in_umbrella: true, ", "")
    if "in_umbrella:" in text or re.search(r"\b(?:path|override):", text):
        raise ValueError("staged manifest contains path, override, or umbrella dependency")
    return text


def stage_sources(stage_dir):
    stage_dir = Path(stage_dir).resolve()
    stage_dir.mkdir(parents=True, exist_ok=True)
    for package in PACKAGES:
        source = ROOT / "apps" / package
        target = stage_dir / package
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(source, target, ignore=shutil.ignore_patterns("_build", "deps", ".git", "plts", "*.plt"))
        manifest = target / "mix.exs"
        manifest.write_text(portable_manifest(manifest.read_text()))
    return stage_dir


def build(stage_dir, version, archive_dir, packages=PACKAGES):
    archive_dir = Path(archive_dir).resolve()
    archive_dir.mkdir(parents=True, exist_ok=True)
    for package in packages:
        archive = archive_dir / f"{package}-{version}.tar"
        subprocess.run(["mix", "hex.build", "--output", str(archive)],
                       cwd=Path(stage_dir) / package, check=True)
    return archive_dir


def verify_rebuild(stage_dir, version, archive_dir, packages=PACKAGES, env=None):
    """Rebuild from unchanged staged sources immediately before publication."""
    archive_dir = Path(archive_dir).resolve()
    for package in packages:
        original = archive_dir / f"{package}-{version}.tar"
        rebuilt = archive_dir / f"{package}-{version}.rebuild.tar"
        subprocess.run(["mix", "hex.build", "--output", str(rebuilt)],
                       cwd=Path(stage_dir) / package, check=True, env=env)
        try:
            if hashlib.sha256(original.read_bytes()).digest() != hashlib.sha256(rebuilt.read_bytes()).digest():
                raise RuntimeError(f"staged package rebuild differs: {package} {version}")
        finally:
            rebuilt.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("build", "verify"))
    parser.add_argument("version")
    parser.add_argument("stage_dir", type=Path)
    parser.add_argument("archive_dir", type=Path)
    parser.add_argument("--package", choices=PACKAGES)
    args = parser.parse_args()
    if not re.fullmatch(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)", args.version):
        parser.error("stable release version required")
    if args.mode == "build":
        build(stage_sources(args.stage_dir), args.version, args.archive_dir,
              (args.package,) if args.package else PACKAGES)
    else:
        verify_rebuild(args.stage_dir, args.version, args.archive_dir)


if __name__ == "__main__":
    main()
