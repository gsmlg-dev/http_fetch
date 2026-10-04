"""Build and optionally publish docs after verified package publication."""

import argparse
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from stage import PACKAGES


def prepare_docs_source(source, target, version):
    shutil.copytree(source, target)
    manifest = target / "mix.exs"
    text = manifest.read_text()
    marker = "deps: deps()"
    if text.count(marker) != 1:
        raise RuntimeError(f"docs staging cannot locate dependency declaration: {source}")
    if "{:ex_doc," not in text:
        text = text.replace(marker, 'deps: deps() ++ [{:ex_doc, "~> 0.38", only: :dev, runtime: false}]')
    pattern = f'https://github.com/gsmlg-dev/http_fetch/blob/v{version}/apps/{source.name}/%{{path}}#L%{{line}}'
    if "docs: [" in text:
        text = text.replace("docs: [", f'docs: [source_url_pattern: "{pattern}", ', 1)
    else:
        text, count = re.subn(
            r"(?m)^(\s*)deps: ",
            lambda match: f'{match.group(1)}docs: [source_url_pattern: "{pattern}"],\n{match.group(1)}deps: ',
            text, count=1,
        )
        if count != 1:
            raise RuntimeError(f"docs staging cannot insert source link pattern: {source}")
    manifest.write_text(text)


def run(version, stage_dir, publish=False):
    if not re.fullmatch(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)", version):
        raise ValueError("stable release version required")
    with tempfile.TemporaryDirectory(prefix="http-fetch-docs-") as directory:
        for package in PACKAGES:
            target = Path(directory) / package
            prepare_docs_source(Path(stage_dir) / package, target, version)
            subprocess.run(["mix", "deps.get"], cwd=target, check=True)
            subprocess.run(["mix", "docs"], cwd=target, check=True)
            if publish:
                subprocess.run(["mix", "hex.publish", "docs", "--yes"], cwd=target, check=True)
            print(f"{'Published' if publish else 'Built'} documentation for {package} {version}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("version")
    parser.add_argument("stage_dir", type=Path)
    parser.add_argument("--publish", action="store_true")
    args = parser.parse_args()
    run(args.version, args.stage_dir, args.publish)


if __name__ == "__main__":
    main()
