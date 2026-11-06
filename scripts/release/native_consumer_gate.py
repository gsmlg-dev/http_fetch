"""Verify the published native package in a cold Hex-only consumer."""

import argparse
from pathlib import Path
import re
import shutil
import tempfile

from consumer_gate import command
from hex_packages import release_status
from server_consumer_gate import isolated_environment, prepare_mix_toolchain
from stage import ROOT


def run(version, archives):
    if not re.fullmatch(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-rc\.(?:0|[1-9]\d*))?", version):
        raise ValueError("canonical shared release version required")
    for package in ("abyss", "abyss_raw"):
        archive = Path(archives) / f"{package}-{version}.tar"
        if not archive.is_file() or release_status(package, version, archive) != "matching":
            raise RuntimeError(f"published native consumer requires matching {package} {version}")
    directory = Path(tempfile.mkdtemp(prefix="http-fetch-native-published-"))
    env = isolated_environment(directory)
    env.pop("CARGO_TARGET_DIR", None)
    env.update(ABYSS_EXPECTED_VERSION=version, ABYSS_RAW_EXPECTED_VERSION=version)
    try:
        prepare_mix_toolchain(directory, env)
        project = directory / "consumer"
        project.mkdir()
        (project / "mix.exs").write_text(f'''defmodule NativeConsumer.MixProject do
  use Mix.Project
  def project, do: [app: :native_consumer, version: "0.0.0",
    deps: [{{:abyss, "== {version}"}}, {{:abyss_raw, "== {version}"}}]]
  def application, do: [extra_applications: [:abyss, :abyss_raw]]
end
''')
        (project / "provenance.exs").write_text(f'''for name <- [:abyss, :abyss_raw] do
  dep = Enum.find(Mix.Dep.cached(), &(&1.app == name))
  unless dep && dep.scm == Hex.SCM && dep.status == {{:ok, "{version}"}} &&
      Path.expand(dep.opts[:dest]) == Path.join([__DIR__, "deps", Atom.to_string(name)]),
    do: raise("native consumer escaped exact Hex dependency: #{{inspect(name)}}")
end
for module <- [Abyss, AbyssDhcpSocket.Native] do
  Code.ensure_loaded!(module)
  unless String.starts_with?(:code.which(module) |> to_string() |> Path.expand(),
                             Path.join(__DIR__, "_build") <> "/"),
    do: raise("native consumer module escaped isolated build")
end
''')
        command(["mix", "deps.get"], cwd=project, env=env)
        command(["mix", "compile", "--warnings-as-errors"], cwd=project, env=env)
        command(["mix", "run", "provenance.exs"], cwd=project, env=env)
        command(["mix", "run", str(ROOT / "apps/abyss/scripts/release/native_smoke.exs")],
                cwd=project, env=env)
        print(f"PASS published native Hex consumer {version}")
    except BaseException:
        print(f"native_consumer_failure_directory={directory}")
        raise
    else:
        shutil.rmtree(directory)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version")
    parser.add_argument("archive_dir", type=Path)
    args = parser.parse_args()
    run(args.version, args.archive_dir)
