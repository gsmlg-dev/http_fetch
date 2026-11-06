"""Build and optionally publish docs after verified package publication."""

import argparse
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from stage import PACKAGES


def prepare_docs_source(source, target, version, *, source_ref=None, source_path=None):
    shutil.copytree(source, target)
    manifest = target / "mix.exs"
    text = manifest.read_text()
    marker = "deps: deps()"
    if "{:ex_doc," not in text:
        if text.count(marker) != 1:
            raise RuntimeError(f"docs staging cannot locate dependency declaration: {source}")
        text = text.replace(marker, 'deps: deps() ++ [{:ex_doc, "~> 0.38", only: :dev, runtime: false}]')
    ref = source_ref or f"v{version}"
    path = source_path or f"apps/{source.name}"
    pattern = f'https://github.com/gsmlg-dev/http_fetch/blob/{ref}/{path}/%{{path}}#L%{{line}}'
    text = re.sub(r'\s*source_url_pattern:\s*"[^"]+",?', "", text)
    if source_ref:
        text = re.sub(r'source_ref:\s*(?:"[^"\n]*"|@version)',
                      f'source_ref: "{source_ref}"', text)
    if "docs: [" in text:
        text = text.replace("docs: [", f'docs: [source_url_pattern: "{pattern}", ', 1)
    elif "docs: docs()" in text:
        text, count = re.subn(r'(defp docs(?:\(\))? do\s*\[)',
                              rf'\1source_url_pattern: "{pattern}", ', text, count=1)
        if count != 1:
            raise RuntimeError(f"docs staging cannot locate docs helper: {source}")
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
    if not re.fullmatch(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-rc\.(?:0|[1-9]\d*))?", version):
        raise ValueError("stable or rc.N release version required")
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
