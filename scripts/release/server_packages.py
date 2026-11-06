"""Independent server release groups; never bump the coordinated client packages.

No mode commits, tags, or pushes. Publication requires the matching immutable
<group>-v<version> tag and an explicit `publish` command.
"""
import argparse
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

from archive_audit import audit_package
from hex_packages import release_status
from stage import GROUPS, ROOT, build, package_path, source_version, stage_sources, verify_rebuild

SERVER_GROUPS = {name: GROUPS[name] for name in ("abyss", "hell")}
VERSION = re.compile(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-rc\.(?:0|[1-9]\d*))?")


def inventory(group):
    groups = SERVER_GROUPS if group == "all" else {group: SERVER_GROUPS[group]}
    result = {}
    for name, packages in groups.items():
        versions = {source_version(ROOT / package_path(package)) for package in packages}
        if len(versions) != 1:
            raise ValueError(f"{name} package versions diverged: {sorted(versions)}")
        version = versions.pop()
        if not VERSION.fullmatch(version):
            raise ValueError(f"invalid {name} version: {version}")
        result.update({package: version for package in packages})
    return result


def prepare(group, version, validate=False):
    if group == "all" or not version or not VERSION.fullmatch(version):
        raise ValueError("prepare/validate --version requires one group and a canonical version")
    changes = {}
    for package in SERVER_GROUPS[group]:
        path = ROOT / package_path(package) / "mix.exs"
        text = path.read_text()
        expression = r'(?<=@version ")[^\"]+(?=")' if '@version "' in text else r'(?<=version: ")[^\"]+(?=")'
        matches = re.findall(expression, text)
        if len(matches) != 1:
            raise ValueError(f"ambiguous version in {path}")
        if validate and matches != [version]:
            raise ValueError(f"{package} version {matches[0]} differs from {version}")
        changes[path] = re.sub(expression, version, text)
    if not validate:
        for path, text in changes.items():
            path.write_text(text)


def audit(stage, archives, versions):
    # Hex performs checksum and metadata decoding, rather than parsing Erlang
    # terms with a permissive text matcher.
    with tempfile.TemporaryDirectory(prefix="server-archive-audit-") as temporary:
        specification = Path(temporary) / "packages.json"
        specification.write_text(json.dumps({name: {"version": version, "archive": str(archives / f"{name}-{version}.tar")}
                                             for name, version in versions.items()}))
        subprocess.run(["elixir", str(ROOT / "scripts/release/server_archives.exs"), str(specification)], check=True)
    for package, version in versions.items():
        audit_package(package, version, stage, archives)
        if package == "abyss_raw":
            with tarfile.open(archives / f"{package}-{version}.tar") as outer:
                contents = outer.extractfile("contents.tar.gz").read()
            with tarfile.open(fileobj=io.BytesIO(contents), mode="r:gz") as inner:
                packed = {member.name for member in inner if member.isfile()}
            expected = {path.relative_to(stage / package).as_posix()
                        for path in (stage / package / "native").rglob("*")
                        if path.is_file()}
            if not expected <= packed:
                raise ValueError(f"abyss_raw omitted native source: {sorted(expected - packed)}")


def docs(stage, packages, publish=False):
    from docs import prepare_docs_source
    with tempfile.TemporaryDirectory(prefix="server-docs-") as temporary:
        for package, version in packages.items():
            target = Path(temporary) / package
            group = "abyss" if package.startswith("abyss") else "hell"
            prepare_docs_source(stage / package, target, version,
                                source_ref=f"{group}-v{version}", source_path=str(package_path(package)))
            # Documentation is repository tooling, so retain its reviewed dev
            # pins rather than floating unrelated helpers during each build.
            lock = ROOT / package_path(package) / "mix.lock" if package == "abyss_raw" else ROOT / "mix.lock"
            shutil.copyfile(lock, target / "mix.lock")
            subprocess.run(["mix", "deps.get"], cwd=target, check=True)
            subprocess.run(["mix", "docs", "--warnings-as-errors"], cwd=target, check=True)
            if publish:
                subprocess.run(["mix", "hex.publish", "docs", "--yes"], cwd=target, check=True)


def publication_identity(group, versions):
    if group == "all":
        raise ValueError("publish exactly one version group")
    version = next(iter(versions.values()))
    tag = f"{group}-v{version}"
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    tagged = subprocess.check_output(["git", "rev-parse", f"refs/tags/{tag}^{{commit}}"], cwd=ROOT, text=True).strip()
    if head != tagged:
        raise ValueError(f"publication requires HEAD at immutable {tag}")
    dirty = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=normal"], cwd=ROOT, text=True)
    if dirty:
        raise ValueError("publication requires a clean checkout")
    if not os.environ.get("HEX_API_KEY"):
        raise ValueError("HEX_API_KEY required")


def publish(group, stage, archives, versions):
    publication_identity(group, versions)
    version = next(iter(versions.values()))
    # Re-stage from the tagged checkout and compare with the supplied candidate,
    # including its portable manifest, before allowing any remote write.
    with tempfile.TemporaryDirectory(prefix="server-tagged-") as temporary:
        fresh = stage_sources(temporary, tuple(versions))
        verify_rebuild(fresh, version, archives, tuple(versions))
    verify_rebuild(stage, version, archives, tuple(versions))
    statuses = {package: release_status(package, value, archives / f"{package}-{value}.tar")
                for package, value in versions.items()}
    for package, value in versions.items():
        if statuses[package] == "missing":
            subprocess.run(["mix", "deps.get", "--only", "prod"], cwd=stage / package, check=True)
            verify_rebuild(stage, value, archives, (package,))
            subprocess.run(["mix", "hex.publish", "package", "--yes"], cwd=stage / package, check=True)
        if release_status(package, value, archives / f"{package}-{value}.tar") != "matching":
            raise RuntimeError(f"published package verification failed: {package}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "validate", "build", "audit", "docs", "publish-docs", "preflight", "publish"))
    parser.add_argument("group", choices=(*SERVER_GROUPS, "all"))
    parser.add_argument("--version")
    parser.add_argument("--stage", type=Path)
    parser.add_argument("--archives", type=Path)
    args = parser.parse_args()
    if args.mode == "prepare":
        prepare(args.group, args.version)
    if args.version and args.mode != "prepare":
        prepare(args.group, args.version, validate=True)
    versions = inventory(args.group)
    if args.mode in ("prepare", "validate"):
        print(json.dumps(versions, sort_keys=True))
        return
    if args.stage is None or (args.mode != "docs" and args.archives is None):
        parser.error("--stage and --archives required (docs needs only --stage)")
    stage = args.stage.resolve()
    archives = args.archives.resolve() if args.archives else None
    if args.mode == "build":
        stage_sources(stage, tuple(versions))
        for package, version in versions.items():
            build(stage, version, archives, (package,))
        audit(stage, archives, versions)
    elif args.mode == "audit":
        audit(stage, archives, versions)
    elif args.mode == "docs":
        docs(stage, versions)
    elif args.mode == "publish-docs":
        publication_identity(args.group, versions)
        audit(stage, archives, versions)
        for package, version in versions.items():
            if release_status(package, version, archives / f"{package}-{version}.tar") != "matching":
                raise ValueError(f"documentation requires verified published {package} {version}")
        with tempfile.TemporaryDirectory(prefix="server-tagged-docs-") as temporary:
            fresh = stage_sources(temporary, tuple(versions))
            verify_rebuild(fresh, next(iter(versions.values())), archives, tuple(versions))
            docs(fresh, versions, publish=True)
    elif args.mode == "preflight":
        audit(stage, archives, versions)
        for package, version in versions.items():
            print(package, release_status(package, version, archives / f"{package}-{version}.tar"))
    elif args.mode == "publish":
        audit(stage, archives, versions)
        publish(args.group, stage, archives, versions)


if __name__ == "__main__":
    main()
