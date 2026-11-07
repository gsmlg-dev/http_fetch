"""Verify isolated candidate or published Hex server packages with real traffic."""

import argparse
from contextlib import nullcontext
import hashlib
import os
from pathlib import Path
import re
import shutil
import tempfile
from urllib.request import urlopen

from consumer_gate import command, local_registry, telemetry_archive
from hex_packages import release_status
from stage import ROOT


def source_versions(packages=("abyss", "hell")):
    versions = {}
    for package in packages:
        source = (ROOT / "apps" / package / "mix.exs").read_text()
        match = re.search(r'@version "([^"]+)"|version: "([^"]+)"', source)
        if not match:
            raise RuntimeError(f"missing source version: {package}")
        versions[package] = next(value for value in match.groups() if value)
    return versions


def locked_package(package):
    line = next((line for line in (ROOT / "mix.lock").read_text().splitlines()
                 if line.lstrip().startswith(f'"{package}":')), "")
    match = re.search(r'\{:hex, :\w+, "([^"]+)",.*"hexpm", "([a-f0-9]{64})"\}', line)
    if not match:
        raise RuntimeError(f"missing locked external package: {package}")
    return match.groups()


def metrics_archive(directory):
    version, checksum = locked_package("telemetry_metrics")
    name = f"telemetry_metrics-{version}.tar"
    cache = Path(os.environ.get("HEX_CACHE_HOME", os.environ.get("HEX_HOME", str(Path.home() / ".hex"))))
    source = cache / "packages/hexpm" / name
    if source.is_file():
        data = source.read_bytes()
    else:
        with urlopen(f"https://repo.hex.pm/tarballs/{name}", timeout=30) as response:
            data = response.read()
    if hashlib.sha256(data).hexdigest() != checksum:
        raise RuntimeError("telemetry_metrics tarball differs from locked outer checksum")
    (directory / name).write_bytes(data)


def isolated_environment(directory):
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("MIX_", "HEX_", "HTTP_FETCH_", "HELL_"))
           and key not in ("ERL_LIBS", "ELIXIR_ERL_OPTIONS")}
    env.update(MIX_ENV="prod", HEX_HOME=str(directory / "hex"),
               HEX_CONFIG_HOME=str(directory / "hex-config"),
               HEX_CACHE_HOME=str(directory / "hex-cache"))
    return env


def prepare_mix_toolchain(directory, env):
    # Hex is build tooling, not a candidate dependency. Copy only that archive
    # into an isolated Mix home instead of retaining inherited code paths.
    mix_home = Path(os.environ.get("MIX_HOME", str(Path.home() / ".mix")))
    archives = Path(os.environ.get("MIX_ARCHIVES", str(mix_home / "archives")))
    candidates = sorted(archives.glob("hex-*"))
    if not candidates:
        raise RuntimeError("installed Hex archive required for signed candidate registry")
    destination = directory / "mix"
    target = destination / "archives" / candidates[-1].name
    shutil.copytree(candidates[-1], target)
    # Older Mix releases install rebar3 directly in MIX_HOME; newer releases
    # put it under an Elixir/OTP-specific directory. Preserve both layouts.
    executables = [mix_home / "rebar3", *(mix_home / "elixir").glob("*/rebar3")]
    for executable in executables:
        if executable.is_file():
            target = destination / executable.relative_to(mix_home)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(executable, target)
    env["MIX_HOME"] = str(destination)


def setup_registry(archive_dir, packages, versions, directory, env):
    public = directory / "public"
    tarballs = public / "tarballs"
    tarballs.mkdir(parents=True)
    for package in packages:
        name = f"{package}-{versions[package]}.tar"
        source = archive_dir / name
        if not source.is_file():
            raise RuntimeError(f"missing candidate archive: {source}")
        shutil.copyfile(source, tarballs / name)
    telemetry_archive(tarballs)
    if "abyss" in packages:
        metrics_archive(tarballs)
    private_key = directory / "registry.pem"
    command(["openssl", "genrsa", "-out", str(private_key), "2048"], cwd=directory, env=env)
    command(["mix", "hex.registry", "build", str(public), "--name=hexpm",
             f"--private-key={private_key}"], cwd=directory, env=env)
    return public


def manifest(package, version, versions=None):
    if package == "quic":
        dependencies = ", ".join(f'{{:{name}, "== {versions[name]}"}}'
                                  for name in ("abyss", "elixir_quic", "ex_ssl"))
        application = "[extra_applications: [:abyss, :elixir_quic, :public_key], mod: {AbyssEchoExample.Application, []}]"
    else:
        dependencies = f'{{:{package}, "== {version}"}}'
        application = f"[extra_applications: [:{package}]]"
    return f'''defmodule ServerConsumer.MixProject do
  use Mix.Project
  def project, do: [app: :server_consumer, version: "0.0.0", deps: [{dependencies}]]
  def application, do: {application}
end
'''


def provenance(package, versions):
    server = "abyss" if package == "quic" else package
    expected = {server: versions[server], "telemetry": locked_package("telemetry")[0]}
    if package in ("abyss", "quic"):
        expected["telemetry_metrics"] = locked_package("telemetry_metrics")[0]
    if package == "quic":
        expected.update({name: versions[name] for name in ("elixir_quic", "ex_ssl")})
    entries = ", ".join(f'{name}: "{version}"' for name, version in expected.items())
    modules = "[Abyss, Telemetry.Metrics]" if package == "abyss" else "[Hell, Hell.Transports.SSL]"
    forbidden = "[Hell, HTTP, Quic, SSL, Rustler, AbyssDhcpSocket.Native]" if package == "abyss" else "[Abyss, HTTP, Quic, SSL, Rustler, AbyssDhcpSocket.Native]"
    if package == "quic":
        modules = "[Abyss, Quic, SSL.QUIC]"
        forbidden = "[Hell, HTTP, Rustler, AbyssDhcpSocket.Native, QUIC]"
    return f'''expected = %{{{entries}}}
deps = Mix.Dep.cached()
unless Enum.sort(Enum.map(deps, & &1.app)) == Enum.sort(Map.keys(expected)),
  do: raise("unexpected dependency closure: #{{inspect(Enum.map(deps, & &1.app))}}")
for dep <- deps do
  unless dep.scm == Hex.SCM and dep.opts[:hex] == Atom.to_string(dep.app) and
      dep.status == {{:ok, Map.fetch!(expected, dep.app)}} and
      Path.expand(dep.opts[:dest]) == Path.join([__DIR__, "deps", Atom.to_string(dep.app)]),
    do: raise("non-isolated Hex dependency: #{{inspect(dep)}}")
end
for module <- {modules} do
  Code.ensure_loaded!(module)
  beam = :code.which(module) |> to_string() |> Path.expand()
  unless String.starts_with?(beam, Path.join(__DIR__, "_build") <> "/"),
    do: raise("module escaped candidate build: #{{inspect(module)}} #{{beam}}")
end
for module <- {forbidden} do
  if Code.ensure_loaded?(module), do: raise("unrelated module visible: #{{inspect(module)}}")
end
unless to_string(Application.spec(:{server}, :vsn)) == "{versions[server]}",
  do: raise("wrong server application version")
IO.puts("PASS {package}: isolated Hex.SCM closure #{{inspect(expected)}}")
'''


UDP_GATE = '''ExUnit.start()
defmodule PlainUdpCandidateTest do
  use ExUnit.Case
  defmodule Echo do
    use Abyss.Handler
    def handle_data({ip, port, payload}, state) do
      :ok = Abyss.Transport.UDP.send(state.socket, ip, port, payload)
      {:close, state}
    end
  end
  test "plain UDP candidate exchanges actual datagrams without optional engines" do
    server = start_supervised!({Abyss, [port: 0, num_listeners: 1, handler_module: Echo,
      transport_options: [ip: {127, 0, 0, 1}]]})
    [listener] = server |> Abyss.Server.listener_pool_pid() |> Abyss.ListenerPool.listener_pids()
    {_, port} = Abyss.Listener.listener_info(listener)
    {:ok, peer} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    try do
      for payload <- ["candidate-udp", "", :binary.copy(<<42>>, 1024)] do
        assert :ok = :gen_udp.send(peer, {127, 0, 0, 1}, port, payload)
        assert {:ok, {{127, 0, 0, 1}, ^port, ^payload}} = :gen_udp.recv(peer, 0, 2000)
      end
    after
      :gen_udp.close(peer)
    end
  end
end
'''


def verify_project(directory, package, versions, env):
    project = directory / package
    project.mkdir()
    server = "abyss" if package == "quic" else package
    (project / "mix.exs").write_text(manifest(package, versions[server], versions))
    (project / "provenance.exs").write_text(provenance(package, versions))
    if package == "hell":
        shutil.copytree(ROOT / "apps/hell/test", project / "test")
        shutil.copyfile(ROOT / "apps/hell/scripts/artifact_smoke.exs", project / "traffic.exs")
        env = {**env, "HELL_TEST_DIR": str(project / "test"),
               "HELL_FIXTURE_DIR": str(project / "test/support"),
               "HELL_EXPECTED_VERSION": versions[package]}
    elif package == "quic":
        source = ROOT / "apps/abyss"
        shutil.copytree(source / "examples/quic_echo/lib", project / "lib")
        fixture = source / "test/fixtures/quic/server_flight"
        env = {**env, "ABYSS_PATH": str(source), "ABYSS_ENGINE_MODE": "candidate",
               "ABYSS_ENGINE_VERSION": versions["elixir_quic"],
               "QUIC_CERT": str(fixture / "leaf.pem"),
               "QUIC_KEY": str(fixture / "leaf-key.pem")}
    else:
        (project / "traffic.exs").write_text(UDP_GATE)
    command(["mix", "deps.get"], cwd=project, env=env)
    command(["mix", "compile", "--warnings-as-errors"], cwd=project, env=env)
    command(["mix", "run", "provenance.exs"], cwd=project, env=env)
    if package == "quic":
        command(["mix", "run", "--no-start", str(source / "scripts/phase1/idle_policy.exs")], cwd=project, env=env)
        command(["mix", "run", str(source / "scripts/phase1/network.exs")], cwd=project, env=env)
        command(["mix", "run", "--no-start", str(source / "scripts/phase1/datagram_test.exs")], cwd=project, env=env)
        command(["mix", "run", str(source / "scripts/phase1/datagram.exs")], cwd=project, env=env)
    else:
        command(["mix", "run", "traffic.exs"], cwd=project, env=env)


def run(archive_dir, mode="all", keep=False, *, published=False):
    consumers = {"all": ("abyss", "hell", "quic"), "udp": ("abyss",),
                 "hell": ("hell",), "quic": ("quic",)}[mode]
    packages = tuple(dict.fromkeys(name for consumer in consumers for name in
                     (("abyss", "elixir_quic", "ex_ssl") if consumer == "quic" else (consumer,))))
    directory = Path(tempfile.mkdtemp(prefix="http-fetch-server-hex-"))
    env = isolated_environment(directory)
    versions = source_versions(packages)
    try:
        prepare_mix_toolchain(directory, env)
        archives = Path(archive_dir).resolve()
        if published:
            for package in packages:
                archive = archives / f"{package}-{versions[package]}.tar"
                if not archive.is_file() or release_status(package, versions[package], archive) != "matching":
                    raise RuntimeError(f"published server package differs or is missing: {package}")
            registry = nullcontext(None)
        else:
            public = setup_registry(archives, packages, versions, directory, env)
            registry = local_registry(public)
        with registry as url:
            if url is not None:
                command(["mix", "hex.repo", "set", "hexpm", "--url", url,
                         "--public-key", str(public / "public_key")], cwd=directory, env=env)
            for package in consumers:
                verify_project(directory, package, versions, env)
        print(f"PASS server Hex {'published packages' if published else 'candidates'}: {', '.join(packages)}")
    except BaseException:
        print(f"server_consumer_failure_directory={directory}")
        raise
    if keep:
        print(f"server_consumer_directory={directory}")
    else:
        shutil.rmtree(directory)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("archive_dir", type=Path)
    parser.add_argument("--mode", choices=("all", "udp", "hell", "quic"), default="all")
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--published", action="store_true")
    args = parser.parse_args()
    run(args.archive_dir, args.mode, args.keep, published=args.published)
