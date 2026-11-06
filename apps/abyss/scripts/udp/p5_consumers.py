#!/usr/bin/env python3
"""Build current package archives and verify independent opt-in consumers."""
import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-wire', action='store_true', help='report isolated DHCP/ARP gates as NOT RUN')
    args = parser.parse_args()
    stage = Path(tempfile.mkdtemp(prefix='abyss-packages-'))
    artifacts = stage / 'artifacts'
    artifacts.mkdir()
    print('PACKAGE_STAGE=' + str(stage), flush=True)
    environment = dict(os.environ, MIX_ENV='prod', CI='true')
    for name in ('MIX_BUILD_PATH', 'MIX_DEPS_PATH', 'CARGO_TARGET_DIR', 'ERL_LIBS'):
        environment.pop(name, None)
    version = re.search(r'@version "([^"]+)"', (ROOT / 'mix.exs').read_text()).group(1)
    for name, source in [('abyss', ROOT), ('abyss_raw', ROOT.parents[1] / 'packages/abyss_raw')]:
        destination = stage / (name + '-source')
        destination.mkdir()
        names = ('mix.exs', 'LICENSE', 'README.md', 'lib', 'docs') if name == 'abyss' else (
            'mix.exs', 'LICENSE', 'README.md', 'lib', 'native')
        for entry in names:
            path = source / entry
            if path.is_dir():
                shutil.copytree(path, destination / entry,
                                ignore=shutil.ignore_patterns('target', '__pycache__'))
            else:
                shutil.copy2(path, destination / entry)
        manifest = destination / 'mix.exs'
        text = manifest.read_text()
        for option in ('build_path', 'deps_path', 'lockfile'):
            text = re.sub(rf'(?m)^\s*{option}: "\.\./\.\./[^"]+",\n', '\n', text)
        manifest.write_text(text)
        subprocess.run(['mix', 'hex.build'], cwd=destination, env=environment, check=True)
        shutil.copy2(destination / f'{name}-{version}.tar', artifacts)
    command = [sys.executable, str(ROOT / 'scripts/release/verify_consumers.py'),
               '--version', version, '--artifacts', str(artifacts), '--legacy',
               '--output', str(stage / 'consumers.json')]
    if not args.no_wire:
        command.append('--wire')
    subprocess.run(command, cwd=ROOT, env=environment, check=True)
    print('PACKAGED_CONSUMERS_PASS ' + str(stage), flush=True)


if __name__ == '__main__':
    main()
