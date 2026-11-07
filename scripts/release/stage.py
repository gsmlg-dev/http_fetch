"""Build coordinated portable Hex archives and the separately published native package."""

import argparse
import hashlib
from pathlib import Path
import re
import shutil
import subprocess

PACKAGES = (
    "ex_ssl", "elixir_quic", "http_core", "http_pool", "elixir_quic_http3", "http_runtime",
    "http_fetch", "http_web_socket", "http_event_source", "http_web_transport",
)
# PACKAGES is the production client/engine proof boundary, including no-OTP SSL.
# Testing support stays outside production and no-OTP release closures.
RELEASE_PACKAGES = (*PACKAGES, "http_test", "abyss", "hell")
NATIVE_PACKAGES = ("abyss_raw",)
ALL_PACKAGES = (*RELEASE_PACKAGES, *NATIVE_PACKAGES)
GROUPS = {"core": PACKAGES, "release": RELEASE_PACKAGES, "native": NATIVE_PACKAGES,
          "abyss": ("abyss", "abyss_raw"), "hell": ("hell",)}
ROOT = Path(__file__).resolve().parents[2]
WORKSPACE_OPTIONS = ("build_path", "config_path", "deps_path", "lockfile")


def portable_manifest(text):
    for option in WORKSPACE_OPTIONS:
        text = re.sub(rf"(?m)^\s*{option}: \"\.\./\.\./[^\"]+\",\n", "\n", text)
    text = text.replace("in_umbrella: true, ", "")
    if "in_umbrella:" in text or re.search(r"\b(?:path|override):", text):
        raise ValueError("staged manifest contains path, override, or umbrella dependency")
    return text


def package_path(package):
    return Path("packages" if package == "abyss_raw" else "apps") / package


def source_version(source):
    match = re.search(r'(?:@version|version:) "([^"]+)"', (Path(source) / "mix.exs").read_text())
    if match is None:
        raise ValueError(f"missing package version: {source}")
    return match.group(1)


def stage_sources(stage_dir, packages=None):
    stage_dir = Path(stage_dir).resolve()
    stage_dir.mkdir(parents=True, exist_ok=True)
    for package in PACKAGES if packages is None else packages:
        source = ROOT / package_path(package)
        target = stage_dir / package
        if target.exists():
            shutil.rmtree(target)
        def ignore_generated(directory, names):
            ignored = shutil.ignore_patterns("_build", "deps", ".git", "plts", "*.plt", "cover", "doc")(directory, names)
            if Path(directory) == source and "tmp" in names:
                ignored.add("tmp")
            if Path(directory) == source / "priv" and "native" in names:
                ignored.add("native")
            if "native" in Path(directory).relative_to(source).parts and "target" in names:
                ignored.add("target")
            return ignored
        shutil.copytree(source, target, ignore=ignore_generated)
        manifest = target / "mix.exs"
        manifest.write_text(portable_manifest(manifest.read_text()))
    return stage_dir


def build(stage_dir, version, archive_dir, packages=PACKAGES):
    archive_dir = Path(archive_dir).resolve()
    archive_dir.mkdir(parents=True, exist_ok=True)
    for package in packages:
        actual = source_version(Path(stage_dir) / package)
        if actual != version:
            raise ValueError(f"{package} version {actual} differs from requested {version}")
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
    parser.add_argument("--package", choices=ALL_PACKAGES)
    parser.add_argument("--group", choices=GROUPS, default="release")
    args = parser.parse_args()
    if not re.fullmatch(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-rc\.(?:0|[1-9]\d*))?", args.version):
        parser.error("stable or rc.N release version required")
    if args.mode == "build":
        packages = (args.package,) if args.package else GROUPS[args.group]
        staged = (stage_sources(args.stage_dir) if packages == PACKAGES
                  else stage_sources(args.stage_dir, packages))
        build(staged, args.version, args.archive_dir, packages)
    else:
        verify_rebuild(args.stage_dir, args.version, args.archive_dir,
                       (args.package,) if args.package else GROUPS[args.group])


if __name__ == "__main__":
    main()
