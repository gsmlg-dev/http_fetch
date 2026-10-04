"""Compare every packaged source byte with the staged portable source tree."""

import argparse
import io
from pathlib import Path
import re
import tarfile

from stage import PACKAGES


def audit_package(package, version, stage_dir, archive_dir):
    source = Path(stage_dir) / package
    archive = Path(archive_dir) / f"{package}-{version}.tar"
    with tarfile.open(archive, "r") as outer:
        content_member = outer.extractfile("contents.tar.gz")
        if content_member is None:
            raise RuntimeError(f"{package} has no Hex content archive")
        content = content_member.read()
    with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as inner:
        members = {member.name: member for member in inner.getmembers()}
        packed = {name for name, member in members.items() if member.isfile()}
        expected_runtime = {str(path.relative_to(source)) for path in (source / "lib").rglob("*.ex")}
        expected_runtime.add("mix.exs")
        missing = expected_runtime - packed
        if missing:
            raise RuntimeError(f"{package} archive omitted runtime source: {sorted(missing)}")
        for name in packed:
            if name.startswith(("test/", "e2e/", "_build/", "deps/", "priv/plts/")) or ".." in Path(name).parts:
                raise RuntimeError(f"{package} archive includes forbidden path: {name}")
            staged = source / name
            if not staged.is_file():
                raise RuntimeError(f"{package} archive includes file absent from stage: {name}")
            extracted = inner.extractfile(members[name])
            if extracted is None or extracted.read() != staged.read_bytes():
                raise RuntimeError(f"{package} archive source differs from stage: {name}")
        manifest = (source / "mix.exs").read_text()
        explicit_files = re.search(r"files:\s*\[([^]]+)\]", manifest)
        listed = explicit_files.group(1) if explicit_files else ""
        for name in ("LICENSE", "README.md", "CHANGELOG.md"):
            if (source / name).is_file() and (name == "LICENSE" or f'"{name}"' in listed) and name not in packed:
                raise RuntimeError(f"{package} archive omitted {name}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("version")
    parser.add_argument("stage_dir", type=Path)
    parser.add_argument("archive_dir", type=Path)
    args = parser.parse_args()
    for package in PACKAGES:
        audit_package(package, args.version, args.stage_dir, args.archive_dir)
    print("all nine archives match staged runtime sources and portable manifests")


if __name__ == "__main__":
    main()
