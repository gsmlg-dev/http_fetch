"""Bind the finite reviewed release proof; never infer callable origins."""
from collections import Counter
import hashlib
import json
from pathlib import Path


SCOPE = 'supported_public_api_and_approved_callbacks'
GROUPS = ('tls', 'quic', 'http', 'h3', 'telemetry')


def require(condition, message):
    if not condition:
        raise ValueError('directed release proof: ' + message)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(source, version, packages):
    """Every source and review is pinned, including files with no generic finding."""
    source = Path(source)
    bundle = json.loads((source / 'docs/no-otp-directed-release.json').read_text())
    require(bundle['schema'] == 1 and bundle['scope'] == SCOPE, 'review scope changed')
    expected_reviews = {f'docs/no-otp-directed-{group}-proof.{extension}'
                        for group in GROUPS for extension in ('md', 'json')}
    require(set(bundle['reviews']) == expected_reviews, 'review set incomplete')
    for name, expected in bundle['reviews'].items():
        require(sha256(source / name) == expected, f'review changed: {name}')
    census = {str(path.relative_to(source / 'apps')): sha256(path)
              for package in packages for path in sorted((source / 'apps' / package / 'lib').rglob('*'))
              if path.is_file()}
    require(census == bundle['sources'], 'complete production source census changed')
    for name, expected in bundle['configuration'].items():
        require(sha256(source / name) == expected, f'reviewed configuration changed: {name}')
    occurrences = []
    for group in GROUPS:
        proof = json.loads((source / f'docs/no-otp-directed-{group}-proof.json').read_text())
        for name, expected in proof['source_inputs_sha256'].items():
            require(sha256(source / name) == expected, f'reviewed producer changed: {name}')
        occurrences.extend(proof['occurrences'])
        if group == 'telemetry':
            dependency = proof['dependency']
            require(dependency['package'] == 'telemetry' and dependency['version'] == '1.4.2',
                    'unreviewed production dependency')
            bundle['sources'].update({f'telemetry/{name}': digest
                                      for name, digest in dependency['source_inputs_sha256'].items()})
    require(sorted(item['inventory_occurrence'] for item in occurrences) == list(range(1, 181)),
            'reviewed occurrence coverage is incomplete or duplicated')
    require(all(bundle['dependency_sources'].get(name) == digest
                for name, digest in bundle['sources'].items() if name.startswith('telemetry/')),
            'dependency source review differs')
    bundle['sources'].update(bundle['dependency_sources'])
    bundle['occurrences'] = [{key: item[key] for key in ('module', 'mfa', 'line', 'kind', 'proof')} |
                             {'source': item['source'].removeprefix('apps/').replace('telemetry-1.4.2/', 'telemetry/')}
                             for item in occurrences]
    bundle['versions'] = {package: version for package in packages} | {
        'telemetry': '1.4.2', 'no_otp_consumer': '0.0.0'}
    for stem in ('no_otp_consumer', 'no_otp_release_audit', 'no_otp_directed_review'):
        bundle['sources'][f'no_otp_consumer/lib/{stem}.ex'] = sha256(
            source / f'scripts/release/{stem}.exs')
    return bundle


def validate(artifacts, bundle):
    """Independently reconcile the native receipt with the untouched audit."""
    receipt = artifacts.get('directed_review', {})
    require(receipt.get('status') == 'PASS' and receipt.get('scope') == SCOPE,
            'native source/BEAM binding did not pass')
    require(receipt.get('reviews') == bundle['reviews'] and receipt.get('sources') == bundle['sources'],
            'native review/source census differs')
    inspections = artifacts.get('beam_inspections', [])
    bindings = receipt.get('beam_bindings', [])
    require(len(bindings) == len(inspections) == artifacts['checked_beams'] > 0,
            'compiled module binding census incomplete')
    by_module = {item['module']: item for item in inspections}
    require(len(by_module) == len(inspections) and
            Counter(item['module'] for item in bindings) == Counter(by_module.keys()),
            'compiled module binding duplicated or missing')
    for item in bindings:
        inspection = by_module[item['module']]
        require(item['beam'] == inspection['beam'] and
                item['sha256'] == item['build_sha256'] == inspection['sha256'],
                'actual release/build BEAM identity differs')
        require(item['source'] in bundle['sources'] and
                item['source_sha256'] == bundle['sources'][item['source']],
                'compiled source lacks a reviewed body')
    raw = artifacts['unresolved_dispatch']
    reviewed = receipt.get('reviewed_dispatches', [])
    require(receipt.get('remaining_dispatches') == [] and
            receipt.get('raw_dispatch_count') == len(raw) == len(reviewed),
            'unproved dispatch remains')
    key = lambda item: (item['beam'], item['line'], item['kind'])
    require(Counter(map(key, raw)) == Counter(map(key, reviewed)),
            'reviewed dispatches differ from original findings')
    identity = lambda item: tuple(item[name] for name in ('module', 'mfa', 'line', 'kind', 'source', 'proof'))
    require(Counter(map(identity, reviewed)) == Counter(map(identity, bundle['occurrences'])),
            'compiled occurrence proof differs from source review')
    for item in reviewed:
        inspection = by_module.get(item['module'])
        require(inspection is not None and item['beam'] == inspection['beam'] and
                item['beam_sha256'] == inspection['sha256'], 'dispatch BEAM binding differs')
