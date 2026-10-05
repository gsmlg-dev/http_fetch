"""Stage the immutable pre-migration HTTP packages for ex_ssl 0.7.2 tests."""

import argparse
from pathlib import Path
import subprocess
import tarfile
import tempfile

HISTORICAL_COMMIT = "e844ce03067fedac82c079f21c47810e671be0bb"
PACKAGES = (
    "http_core", "http_runtime", "http_fetch", "http_web_socket",
    "http_event_source", "http_web_transport",
)


def stage(repository, commit, destination):
    if commit != HISTORICAL_COMMIT:
        raise ValueError(f"historical source must be pinned to {HISTORICAL_COMMIT}")
    destination = Path(destination).resolve()
    if destination.exists():
        raise ValueError(f"historical stage already exists: {destination}")
    paths = ["mix.exs", "mix.lock", "LICENSE", "README.md", "CHANGELOG.md"]
    paths += [f"apps/{package}" for package in PACKAGES]
    with tempfile.TemporaryDirectory() as temporary:
        archive = Path(temporary) / "history.tar"
        subprocess.run(["git", "archive", "--format=tar", "-o", str(archive),
                        commit, "--", *paths], cwd=repository, check=True)
        destination.mkdir(parents=True)
        with tarfile.open(archive) as contents:
            contents.extractall(destination, filter="data")

    # Hex rejects package files that link outside their package directory.
    # Replace only the historical source's links with their original bytes.
    for package in PACKAGES:
        package_dir = destination / "apps" / package
        for path in package_dir.rglob("*"):
            if path.is_symlink():
                target = path.resolve(strict=True)
                if not target.is_relative_to(destination):
                    raise ValueError(f"historical package link escapes source: {path}")
                data = target.read_bytes()
                path.unlink()
                path.write_bytes(data)
    return destination


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("repository", type=Path)
    parser.add_argument("commit")
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    stage(args.repository, args.commit, args.destination)
