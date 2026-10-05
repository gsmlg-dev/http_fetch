"""Resolve and compile every candidate package through a signed local Hex registry."""

import argparse
from contextlib import contextmanager
import hashlib
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
from urllib.request import urlopen

from stage import PACKAGES, ROOT


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass


def command(args, *, cwd=None, env=None):
    subprocess.run(args, cwd=cwd, env=env, check=True)


def telemetry_archive(destination):
    source = Path.home() / ".hex/packages/hexpm/telemetry-1.3.0.tar"
    lock = (ROOT / "mix.lock").read_text()
    match = re.search(r'"telemetry": \{:hex, :telemetry, "1\.3\.0", "[a-f0-9]+", \[:rebar3\], \[\], "hexpm", "([a-f0-9]+)"\}', lock)
    if not match:
        raise RuntimeError("expected locked telemetry 1.3.0 package")
    if source.is_file():
        data = source.read_bytes()
    else:
        with urlopen("https://repo.hex.pm/tarballs/telemetry-1.3.0.tar", timeout=30) as response:
            data = response.read()
    if hashlib.sha256(data).hexdigest() != match.group(1):
        raise RuntimeError("telemetry tarball differs from locked outer checksum")
    destination.write_bytes(data)


def setup_registry(archive_dir, version, directory, env):
    public = directory / "public"
    tarballs = public / "tarballs"
    tarballs.mkdir(parents=True)
    for package in PACKAGES:
        archive = archive_dir / f"{package}-{version}.tar"
        if not archive.is_file():
            raise RuntimeError(f"missing candidate archive: {archive}")
        shutil.copyfile(archive, tarballs / archive.name)
    telemetry_archive(tarballs / "telemetry-1.3.0.tar")
    private_key = directory / "registry.pem"
    command(["openssl", "genrsa", "-out", str(private_key), "2048"])
    command(["mix", "hex.registry", "build", str(public), "--name=hexpm", f"--private-key={private_key}"], env=env)
    return public


@contextmanager
def local_registry(public):
    handler = lambda *args, **kwargs: QuietHandler(*args, directory=str(public), **kwargs)
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def verify_project(project, package, version, env):
    source = f'''defmodule CandidateConsumer.MixProject do
  use Mix.Project
  def project, do: [app: :candidate_consumer, version: "0.0.0", deps: [{{:{package}, "== {version}"}}]]
  def application, do: [extra_applications: [:logger]]
end
'''
    if "path:" in source or "override:" in source or "in_umbrella:" in source:
        raise RuntimeError("consumer dependency must use Hex SCM")
    (project / "mix.exs").write_text(source)
    (project / "verify.exs").write_text(f'''expected = "{version}"
for app <- ~w({" ".join(PACKAGES)})a do
  if dep = Enum.find(Mix.Dep.cached(), &(&1.app == app)) do
    unless dep.scm == Hex.SCM and dep.status == {{:ok, expected}} do
      raise "invalid Hex resolution for #{{app}}: #{{inspect(dep)}}"
    end
  end
end
{{:ok, _}} = Application.ensure_all_started(:{package})
unless Application.spec(:{package}, :vsn) |> to_string() == expected,
  do: raise("wrong application version")
IO.puts("Hex consumer verified {package} #{{expected}}")
''')
    command(["mix", "deps.get"], cwd=project, env=env)
    command(["mix", "compile", "--warnings-as-errors"], cwd=project, env=env)
    command(["mix", "run", "verify.exs"], cwd=project, env=env)


def runtime_projects(directory, version, env):
    clients = ("http_fetch", "http_event_source", "http_web_socket")
    for selected in ((clients[0],), (clients[1],), (clients[2],), clients):
        project = directory / "runtime" / "-".join(selected)
        project.mkdir(parents=True)
        deps = ", ".join(f'{{:{app}, "== {version}"}}' for app in selected)
        (project / "mix.exs").write_text(f'''defmodule RuntimeConsumer.MixProject do
  use Mix.Project
  def project, do: [app: :runtime_consumer, version: "0.1.0", deps: [{deps}]]
  def application, do: [extra_applications: [:logger]]
end
''')
        shutil.copyfile(ROOT / "scripts/http_runtime_consumer_gate.exs", project / "gate.exs")
        project_env = {**env, "HTTP_RUNTIME_CONSUMER_CLIENTS": ",".join(selected),
                       "HTTP_RUNTIME_CONSUMER_RELEASE": version,
                       "HTTP_RUNTIME_REPO_ROOT": str(ROOT),
                       "MIX_BUILD_PATH": str(project / "build")}
        command(["mix", "deps.get"], cwd=project, env=project_env)
        command(["mix", "compile", "--warnings-as-errors"], cwd=project, env=project_env)
        command(["mix", "run", "gate.exs", "verify"], cwd=project, env=project_env)


def external_project(directory, version, env):
    project = directory / "external"
    project.mkdir(parents=True)
    clients = ("http_core", "http_runtime", "http_fetch", "http_web_socket",
               "http_event_source", "http_web_transport")
    deps = ", ".join(f'{{:{app}, "== {version}"}}' for app in clients)
    (project / "mix.exs").write_text(f'''defmodule ExternalConsumer.MixProject do
  use Mix.Project
  def project, do: [app: :external_consumer, version: "0.1.0", deps: [{deps}]]
  def application, do: [extra_applications: [:logger, :public_key, :ssl]]
end
''')
    shutil.copyfile(ROOT / "scripts/external_consumer_smoke.exs", project / "smoke.exs")
    fixtures = ROOT / "apps/http_fetch/test/support/fixtures"
    project_env = {**env, "HTTP_FETCH_PACKAGE_DIR": str(project / "deps"),
                   "HTTP_FETCH_RELEASE_VERSION": version,
                   "HTTP_FETCH_CERTFILE": str(fixtures / "localhost.pem"),
                   "HTTP_FETCH_CACERTFILE": str(fixtures / "localhost-ca.pem"),
                   "HTTP_FETCH_KEYFILE": str(fixtures / "localhost.key")}
    command(["mix", "deps.get"], cwd=project, env=project_env)
    command(["mix", "compile", "--warnings-as-errors"], cwd=project, env=project_env)
    command(["mix", "run", "smoke.exs"], cwd=project, env=project_env)


def feature_group_passed(output):
    old = re.search(r"(?m)^[1-9][0-9]* tests?, 0 failures$", output)
    current = re.search(r"(?m)^Result: [1-9][0-9]* passed$", output)
    skipped = re.search(r"(?m)[1-9][0-9]* (?:excluded|skipped)", output)
    return bool(old or current) and not skipped


def feature_project(directory, version, env):
    project = directory / "feature"
    (project / "test").mkdir(parents=True)
    clients = ("http_fetch", "http_web_socket", "http_event_source", "http_web_transport", "ex_ssl")
    deps = ", ".join(f'{{:{app}, "== {version}"}}' for app in clients)
    (project / "mix.exs").write_text(f'''defmodule ExSslFeatureConsumer.MixProject do
  use Mix.Project
  def project, do: [app: :ex_ssl_feature_consumer, version: "0.0.0", deps: [{deps}]]
  def application, do: [extra_applications: [:logger, :ssl, :public_key]]
end
''')
    (project / "test/test_helper.exs").write_text("ExUnit.start()\n")
    groups = sorted((ROOT / "scripts").glob("ex_ssl_*_test.exs"))
    if len(groups) < 9:
        raise RuntimeError("candidate TLS feature groups are missing")
    for group in groups:
        shutil.copyfile(group, project / "test" / group.name)
    shutil.copyfile(ROOT / "scripts/ex_ssl_tls12_peer.py", project / "test/ex_ssl_tls12_peer.py")
    test_env = {**env, "MIX_ENV": "test"}
    command(["mix", "deps.get"], cwd=project, env=test_env)
    command(["mix", "compile", "--warnings-as-errors"], cwd=project, env=test_env)
    provenance = subprocess.run(["mix", "run", "-e", f'''dep = Enum.find(Mix.Dep.cached(), &(&1.app == :ex_ssl)) || raise("missing ex_ssl")
unless dep.scm == Hex.SCM and dep.status == {{:ok, "{version}"}}, do: raise("candidate ex_ssl is not Hex SCM")
IO.puts("runtime=hex-candidate/{version}")
IO.puts("resolved_scm=Hex.SCM")
IO.puts("loaded_ssl_connection=" <> to_string(:code.which(SSL.Connection)))
'''], cwd=project, env=test_env, capture_output=True, text=True, check=True)
    provenance_file = os.environ.get("EX_SSL_PROVENANCE_LOG")
    if provenance_file:
        Path(provenance_file).write_text(provenance.stdout)
    print(provenance.stdout, end="")
    logs = Path(os.environ.get("EX_SSL_GROUP_LOG_DIR", directory / "groups"))
    logs.mkdir(parents=True, exist_ok=True)
    seed = os.environ.get("EX_SSL_TEST_SEED", "36")
    for group in groups:
        result = subprocess.run(["mix", "test", f"test/{group.name}", "--seed", seed],
                                cwd=project, env=test_env, capture_output=True, text=True)
        output = result.stdout + result.stderr
        (logs / f"{group.name}.log").write_text(output)
        print(f"{group.name}: {result.returncode}")
        if result.returncode or not feature_group_passed(output):
            print(output[-6000:])
            raise RuntimeError(f"candidate TLS feature group failed: {group.name}")


def run(version, archive_dir, *, mode="all", keep=False):
    if not re.fullmatch(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)", version):
        raise ValueError("stable release version required")
    archive_dir = Path(archive_dir).resolve()
    directory = Path(tempfile.mkdtemp(prefix="http-fetch-hex-consumer-"))
    env = {**os.environ, "HEX_HOME": str(directory / "hex"), "MIX_ENV": "prod"}
    env.pop("HTTP_FETCH_CI_APP", None)
    env.pop("MIX_BUILD_PATH", None)
    env.pop("MIX_DEPS_PATH", None)
    try:
        public = setup_registry(archive_dir, version, directory, env)
        with local_registry(public) as url:
            command(["mix", "hex.repo", "set", "hexpm", "--url", url,
                     "--public-key", str(public / "public_key")], env=env)
            if mode == "all":
                for package in PACKAGES:
                    project = directory / "consumers" / package
                    project.mkdir(parents=True)
                    verify_project(project, package, version, env)
            elif mode == "runtime":
                runtime_projects(directory, version, env)
            elif mode == "external":
                external_project(directory, version, env)
            elif mode == "feature":
                feature_project(directory, version, env)
            else:
                raise ValueError(f"unknown consumer mode: {mode}")
        if keep:
            print(f"candidate_consumer_directory={directory}")
        else:
            shutil.rmtree(directory)
    except BaseException:
        # Keep failures for inspection unless caller asks for normal cleanup.
        print(f"candidate_consumer_failure_directory={directory}")
        raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("version")
    parser.add_argument("archive_dir", type=Path)
    parser.add_argument("--mode", choices=("all", "runtime", "external", "feature"), default="all")
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    run(args.version, args.archive_dir, mode=args.mode, keep=args.keep)


if __name__ == "__main__":
    main()
