#!/usr/bin/env python3
"""Run the unchanged #108 concurrent Abyss workload against staged or Hex QUIC.

Requires mix, uv and network access. All dependency/build files are disposable.
The pinned peer retains its exact payload/FIN assertions and 25-second deadlines.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
ABYSS_COMMIT = "9b710e6480900e16e304f40e63623aff8c922e19"
ABYSS_URL = f"https://codeload.github.com/gsmlg-dev/abyss/tar.gz/{ABYSS_COMMIT}"
ABYSS_CONTENT_HASH = "a0e61f37d81bc8d98972296e869e1e9fee82c726e7be07ac5c0aea2a5eb45038"


def command(args, cwd, env, timeout):
    process = subprocess.Popen(args, cwd=cwd, env=env, start_new_session=True)
    try:
        status = process.wait(timeout=timeout)
    except BaseException:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        raise
    if status:
        raise subprocess.CalledProcessError(status, args)


def run(archive=None, published=None):
    if published is None:
        spec = importlib.util.spec_from_file_location("release_stage", ROOT / "scripts/release/stage.py")
        stage = importlib.util.module_from_spec(spec)
        sys.dont_write_bytecode = True
        spec.loader.exec_module(stage)

    with tempfile.TemporaryDirectory(prefix="http-fetch-abyss-concurrent-") as directory:
        workspace = Path(directory)
        if archive is None:
            archive = workspace / "abyss.tar.gz"
            urllib.request.urlretrieve(ABYSS_URL, archive)
        unpacked = workspace / "upstream"
        with tarfile.open(archive) as source:
            source.extractall(unpacked, filter="data")
        abyss = unpacked / f"abyss-{ABYSS_COMMIT}"
        if not abyss.exists():
            # Also accept a local git archive of this same pinned revision.
            abyss = unpacked
        digest = hashlib.sha256()
        for path in sorted(path for path in abyss.rglob("*") if path.is_file()):
            digest.update(path.relative_to(abyss).as_posix().encode() + b"\0"
                          + hashlib.sha256(path.read_bytes()).digest())
        if digest.hexdigest() != ABYSS_CONTENT_HASH:
            raise RuntimeError("Abyss archive does not match the pinned baseline content")
        consumer = workspace / "consumer"
        shutil.copytree(abyss / "examples/quic_echo/lib", consumer / "lib")
        if published is None:
            for package in ("ex_ssl", "elixir_quic"):
                target = workspace / package
                shutil.copytree(ROOT / "apps" / package, target,
                                ignore=shutil.ignore_patterns("_build", "deps", ".git", "plts", "*.plt"))
                manifest = target / "mix.exs"
                manifest.write_text(stage.portable_manifest(manifest.read_text()))

        manifest = (abyss / "examples/quic_echo/mix.exs").read_text()
        if published is None:
            dependencies = (
                '{:elixir_quic, path: ' + json.dumps(str(workspace / "elixir_quic")) + ', override: true},\n'
                '        {:ex_ssl, path: ' + json.dumps(str(workspace / "ex_ssl")) + ', override: true}')
        else:
            dependencies = (
                '{:elixir_quic, "== ' + published + '"},\n'
                '        {:ex_ssl, "== ' + published + '"}')
        manifest = manifest.replace(
            '{:elixir_quic, "== 0.17.0"}', dependencies)
        if dependencies not in manifest:
            raise RuntimeError("pinned Abyss consumer manifest changed")
        (consumer / "mix.exs").write_text(manifest)
        fixture = abyss / "test/fixtures/quic/server_flight"
        env = dict(os.environ, MIX_ENV="prod", ABYSS_PATH=str(abyss),
                   HEX_HOME=str(workspace / "hex"),
                   MIX_BUILD_PATH=str(workspace / "build"), MIX_DEPS_PATH=str(consumer / "deps"),
                   QUIC_CERT=str(fixture / "leaf.pem"), QUIC_KEY=str(fixture / "leaf-key.pem"),
                   QUIC_PORT="0")
        for name in ("HEX_MIRROR", "HEX_TRUSTED_MIRROR", "HTTP_FETCH_CI_APP"):
            env.pop(name, None)
        source_root = consumer / "deps" if published else workspace
        proof = consumer / "run.exs"
        proof.write_text(
            'for {module, package} <- [{Quic.Recovery, "elixir_quic"}, {SSL, "ex_ssl"}] do\n'
            '  path = module.module_info(:compile)[:source] |> to_string()\n'
            '  unless String.starts_with?(path, Path.join(' + json.dumps(str(source_root)) + ', package)),\n'
            '    do: raise("unexpected loaded source: #{path}")\n'
            '  IO.puts("CONCURRENT_SOURCE #{module}: #{path}")\n'
            'end\n'
            + ('for app <- [:elixir_quic, :ex_ssl] do\n'
               '  Application.load(app)\n'
               f'  "{published}" = to_string(Application.spec(app, :vsn))\n'
               'end\n'
               if published else '') +
            '{:ok, _} = Application.ensure_all_started(:abyss_quic_echo_example)\n'
            'Code.require_file(Path.join(System.fetch_env!("ABYSS_PATH"), "scripts/phase1/network.exs"))\n')
        print(f"ABYSS_CONCURRENT_BASELINE {ABYSS_COMMIT}", flush=True)
        print(f"ABYSS_CONCURRENT_PACKAGES {published or 'staged source'}", flush=True)
        for args in (["mix", "deps.get"], ["mix", "compile", "--warnings-as-errors"],
                        ["mix", "run", "--no-start", str(proof)]):
            command(args, consumer, env, 180 if args[1] == "run" else 600)
            if published and args[1] == "deps.get":
                lock = (consumer / "mix.lock").read_text()
                for package in ("elixir_quic", "ex_ssl"):
                    if not re.search(rf'"{package}": \{{:hex, :{package}, "{re.escape(published)}",', lock):
                        raise RuntimeError(f"{package} did not resolve from Hex at {published}")
                print(lock, flush=True)
        print("ABYSS_CONCURRENT_PASS", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--abyss-archive", type=Path,
                        help=f"local git archive of Abyss {ABYSS_COMMIT} (otherwise downloaded)")
    parser.add_argument("--published", help="exact stable Hex version instead of staged source")
    args = parser.parse_args()
    if args.published and not re.fullmatch(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)", args.published):
        parser.error("stable release version required")
    run(args.abyss_archive, args.published)
