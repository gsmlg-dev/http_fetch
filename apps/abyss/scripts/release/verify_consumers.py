#!/usr/bin/env python3
"""Verify extracted release archives and fresh, exact-version Hex consumers."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
PACKAGES = ("abyss", "abyss_raw")


def run(command, cwd, environment):
    print("COMMAND", str(cwd), command, flush=True)
    subprocess.run(command, cwd=cwd, env=environment, check=True)


def download(url):
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read()


def unpack(archive, destination):
    destination.mkdir()
    with tarfile.open(archive) as outer:
        contents = outer.extractfile("contents.tar.gz").read()
    with tarfile.open(fileobj=io.BytesIO(contents), mode="r:gz") as inner:
        inner.extractall(destination, filter="data")


def no_rust_path(directory):
    directory.mkdir()
    for name in ("elixir", "mix", "erl", "erlc", "escript", "rebar3", "sh", "bash",
                 "dirname", "readlink", "basename", "sed", "grep", "uname", "env",
                 "mkdir", "rm", "curl", "tar", "gzip", "git"):
        executable = shutil.which(name)
        if executable:
            (directory / name).symlink_to(executable)
    return str(directory)


def consumer(directory, version, optional, published, core_package, raw_package):
    directory.mkdir()
    if published:
        dependencies = [f'{{:abyss, "== {version}"}}']
        if optional:
            dependencies.append(f'{{:abyss_raw, "== {optional}"}}')
    else:
        dependencies = [f'{{:abyss, path: "{core_package}"}}']
        if optional:
            dependencies.append(f'{{:abyss_raw, path: "{raw_package}"}}')
    (directory / "mix.exs").write_text('''defmodule ReleaseConsumer.MixProject do
  use Mix.Project
  def project do
    [app: :release_consumer, version: "0.0.0",
     releases: [release_consumer: [include_executables_for: [:unix]]],
     deps: [''' + ", ".join(dependencies) + ''']]
  end
  def application, do: [extra_applications: [:logger]]
end
''')


def assert_installed_source(consumer_path, archives, published):
    if not published:
        return
    for name, source in archives.items():
        installed = consumer_path / "deps" / name
        if not installed.exists():
            continue
        for path in source.rglob("*"):
            if path.is_file():
                relative = path.relative_to(source)
                assert (installed / relative).read_bytes() == path.read_bytes(), (name, relative)


def verify(args):
    stage = Path(tempfile.mkdtemp(prefix="abyss-release-consumers-"))
    print("CONSUMER_STAGE=" + str(stage), flush=True)
    environment = dict(os.environ, MIX_ENV="prod", CI="true", HEX_HOME=str(stage / "hex"))
    for name in ("MIX_BUILD_PATH", "MIX_DEPS_PATH", "CARGO_TARGET_DIR", "ERL_LIBS"):
        environment.pop(name, None)
    archives = {}
    evidence = {"version": args.version, "published": args.published, "stage": str(stage),
                "packages": {}, "gates": []}
    for name in PACKAGES:
        archive = args.artifacts / f"{name}-{args.version}.tar"
        expected = archive.read_bytes()
        if args.published:
            metadata = json.loads(download(f"https://hex.pm/api/packages/{name}/releases/{args.version}"))
            actual = download(f"https://repo.hex.pm/tarballs/{name}-{args.version}.tar")
            digest = hashlib.sha256(actual).hexdigest()
            assert digest == metadata["checksum"], (name, "registry checksum mismatch")
            assert actual == expected, (name, "GitHub/release archive differs from Hex")
            assert metadata["has_docs"], (name, "Hex documentation missing")
            assert metadata["meta"]["app"] == name
            requirements = metadata["requirements"]
            assert not (set(requirements) & ({"abyss", "abyss_raw", "abyss_dhcp_socket"} - {name}))
            if name == "abyss":
                assert "rustler" not in requirements
        unpack(archive, stage / (name + "-package"))
        archives[name] = stage / (name + "-package")
        evidence["packages"][name] = {"sha256": hashlib.sha256(expected).hexdigest()}

    core, raw = archives["abyss"], archives["abyss_raw"]
    for path in core.rglob("*"):
        assert not set(path.relative_to(core).parts) & {"native", "priv", "packages"}, path
        assert path.suffix not in (".rs", ".so", ".dylib", ".dll"), path
        assert path.name not in ("Cargo.toml", "Cargo.lock"), path
    assert (raw / "native/dhcp_socket/Cargo.lock").is_file()
    assert not (raw / "priv").exists(), "Hex package builds native artifacts on the target platform"

    # This source tree has no parent repository and must build as an independent project.
    standalone = stage / "standalone-raw"
    shutil.copytree(raw, standalone)
    run(["mix", "deps.get"], standalone, environment)
    run(["mix", "compile", "--warnings-as-errors"], standalone, environment)
    run(["mix", "run", "-e", 'true = Code.ensure_loaded?(AbyssDhcpSocket.Native); '
         'IO.puts("STANDALONE_ABYSS_RAW_PASS")'], standalone, environment)
    evidence["gates"].append("standalone_extracted_raw")

    plain = stage / "core-consumer"
    consumer(plain, args.version, None, args.published, core, raw)
    core_environment = dict(environment, PATH=no_rust_path(stage / "no-rust-bin"),
                            ABYSS_EXPECTED_VERSION=args.version)
    run(["mix", "deps.get"], plain, core_environment)
    run(["mix", "compile", "--warnings-as-errors"], plain, core_environment)
    run(["mix", "run", str(ROOT / "scripts/udp/p5_core_consumer.exs")], plain, core_environment)
    assert_installed_source(plain, {"abyss": core}, args.published)
    for path in plain.rglob("*"):
        assert path.suffix not in (".so", ".dylib", ".dll"), path
    evidence["gates"].append("core_only_no_rust_udp")

    native = stage / "native-consumer"
    consumer(native, args.version, args.version, args.published, core, raw)
    native_environment = dict(environment, ABYSS_EXPECTED_VERSION=args.version,
                              ABYSS_RAW_EXPECTED_VERSION=args.version)
    run(["mix", "deps.get"], native, native_environment)
    run(["mix", "compile", "--warnings-as-errors"], native, native_environment)
    run(["mix", "run", str(ROOT / "scripts/release/native_smoke.exs")], native, native_environment)
    assert_installed_source(native, archives, args.published)
    evidence["gates"].append("combined_native_load_and_operation_errors")
    run(["mix", "release", "--overwrite"], native, native_environment)
    release = native / "_build/prod/rel/release_consumer"
    libraries = list((release / f"lib/abyss_raw-{args.version}/priv/native").glob("*"))
    assert any(path.suffix in (".so", ".dylib", ".dll") for path in libraries), libraries
    release_environment = dict(native_environment)
    release_environment["ABYSS_RELEASE_SMOKE"] = str(ROOT / "scripts/release/native_smoke.exs")
    run([str(release / "bin/release_consumer"), "eval",
         'Code.require_file(System.fetch_env!("ABYSS_RELEASE_SMOKE"))'], native, release_environment)
    evidence["gates"].append("explicit_native_mix_release_artifact")

    if args.legacy:
        legacy_archive = stage / "abyss-0.8.1.tar"
        legacy_archive.write_bytes(download("https://repo.hex.pm/tarballs/abyss-0.8.1.tar"))
        legacy_core = stage / "abyss-legacy-package"
        unpack(legacy_archive, legacy_core)
        legacy = stage / "legacy-consumer"
        consumer(legacy, "0.8.1", args.version, args.published, legacy_core, raw)
        legacy_environment = dict(native_environment, ABYSS_EXPECTED_VERSION="0.8.1")
        run(["mix", "deps.get"], legacy, legacy_environment)
        run(["mix", "compile", "--warnings-as-errors"], legacy, legacy_environment)
        run(["mix", "run", str(ROOT / "scripts/release/native_smoke.exs")], legacy, legacy_environment)
        evidence["gates"].append("released_0_8_1_facade")

    if args.wire:
        run(["python3", str(ROOT / "scripts/udp/dhcp_fixture.py"), "--consumer", str(native)],
            ROOT, native_environment)
        evidence["gates"].append("isolated_dhcp_arp_wire_and_cleanup")
    else:
        evidence["wire"] = "NOT RUN: enable --wire on a Linux namespace-capable host"
    evidence["result"] = "PASS"
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--published", action="store_true")
    parser.add_argument("--legacy", action="store_true")
    parser.add_argument("--wire", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    evidence = verify(args)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps(evidence, indent=2), flush=True)


if __name__ == "__main__":
    main()
