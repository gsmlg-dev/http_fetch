"""Build an isolated candidate or published release and run the no-OTP-SSL gate.

This command starts real build tools and external peers. Unit tests mock those
collaborators. A passing mock run is never production removal evidence.

Usage: python3 no_otp_consumer_gate.py VERSION ARCHIVES STAGE --source-root ROOT
       --source-sha SHA --peer-plan PLAN.json --output NEW_DIRECTORY
       [--published]

Published mode requires all nine Hex archives to match the source-bound release
archives, then resolves packages with fresh Hex configuration and cache paths.

PLAN schema 1 contains pinned external peers and all REQUIRED scenarios. Peers
receive NO_OTP_NONCE in their environment. The structured JSON-line peer protocol
emits {kind:ready, port, identity} followed by independently observed scenario
records (kind:scenario, id, nonce, client, action, tls, alpn, requests, executed,
result, peer_identity, fallback, replay). Its stdin accepts {command:stats}.
Existing performance/h2_websocket/http3 raw peers can also be collected; missing
TLS/reset/replay evidence remains unconfirmed, never synthetic success.
"""

import argparse
from contextlib import contextmanager, nullcontext
import hashlib
import io
import json
import os
from pathlib import Path
import queue
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import threading
import time
import uuid
from urllib.parse import urlsplit

import archive_audit
import consumer_gate
from stage import PACKAGES, portable_manifest

HERE = Path(__file__).resolve().parent
CLIENTS = ('h1', 'h2', 'wss', 'sse', 'managed_h1', 'managed_h2', 'h3')
ACTIONS = ('success', 'invalid_identity', 'timeout', 'cancellation', 'shutdown')
REQUIRED = frozenset((client, action) for client in CLIENTS for action in ACTIONS)
MODULES = ('HTTP', 'SSL.Connection', 'Quic', 'QuicHttp3.Session',
           'HTTP.ManagedTransport', 'HTTP.WebSocket', 'HTTP.EventSource')
PROVENANCE = '''expected = System.fetch_env!("NO_OTP_VERSION")
project = System.fetch_env!("NO_OTP_PROJECT")
packages = ~w(ex_ssl elixir_quic http_core elixir_quic_http3 http_runtime http_fetch http_web_socket http_event_source http_web_transport)a
for app <- packages do
  dep = Enum.find(Mix.Dep.cached(), &(&1.app == app)) || raise("missing candidate #{app}")
  unless dep.scm == Hex.SCM and dep.opts[:hex] == Atom.to_string(app) and
           dep.status == {:ok, expected} and
           Path.expand(dep.opts[:dest]) == Path.join(project, "deps/#{app}"),
    do: raise("non-isolated or wrong-version candidate #{app}")
end
for dep <- Mix.Dep.cached() do
  unless dep.scm == Hex.SCM and dep.opts[:override] in [nil, false] and
           Path.expand(dep.opts[:dest]) == Path.join(project, "deps/#{dep.app}"),
    do: raise("transitive dependency escaped isolated Hex resolution")
end
loaded = for module <- [HTTP, SSL.Connection, Quic, QuicHttp3.Session, HTTP.ManagedTransport, HTTP.WebSocket, HTTP.EventSource] do
  Code.ensure_loaded!(module)
  path = :code.which(module) |> to_string() |> Path.expand()
  unless String.starts_with?(path, Path.join(project, "build") <> "/"),
    do: raise("module escaped candidate build: #{module}")
  {inspect(module), path}
end
IO.puts(JSON.encode!(%{gate: "no_otp_hex_provenance", version: expected, scm: "Hex.SCM", loaded_modules: Map.new(loaded)}))
'''


class GateError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise GateError(message)


def validate_version(version):
    require(isinstance(version, str) and re.fullmatch(
        r'(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-rc\.(?:0|[1-9]\d*))?', version),
        'stable or rc.N coordinated version required')


def validate_plan(plan):
    require(isinstance(plan, dict) and plan.get('schema') == 1, 'peer plan schema 1 required')
    peers = plan.get('peers')
    cases = plan.get('scenarios')
    require(isinstance(peers, dict) and peers, 'external peers required')
    require(isinstance(cases, list) and len(cases) == len(REQUIRED), 'complete scenario matrix required')
    for name, peer in peers.items():
        require(re.fullmatch(r'[a-zA-Z0-9_-]{1,60}', name), 'invalid peer name')
        require(isinstance(peer, dict) and peer.get('kind', 'structured') in
                ('structured', 'performance', 'h2_websocket', 'http3'), 'unknown peer observation adapter')
        require(isinstance(peer.get('argv'), list) and peer['argv'] and
                all(isinstance(arg, str) and arg and '\x00' not in arg for arg in peer['argv']),
                'peer argv required; no shell commands')
        require(isinstance(peer.get('script'), str) and peer['script'] in peer['argv'], 'pin actual peer script')
        require(re.fullmatch(r'[a-f0-9]{64}', peer.get('sha256', '')), 'peer script SHA256 required')
    seen = set()
    identifiers = set()
    for case in cases:
        pair = (case.get('client'), case.get('action'))
        require(pair in REQUIRED and pair not in seen, 'missing/duplicate/unknown mandatory scenario')
        seen.add(pair)
        require(isinstance(case.get('id'), str) and re.fullmatch(r'[a-zA-Z0-9_.-]{1,100}', case['id'])
                and case['id'] not in identifiers, 'unique bounded scenario id required')
        identifiers.add(case['id'])
        require(case.get('peer') in peers, 'scenario peer missing')
        require(case.get('tls') in ('TLSv1.2', 'TLSv1.3'), 'exact peer TLS version required')
        allowed = ('h3',) if case['client'] == 'h3' else (
            ('http/1.1',) if case['client'] in ('h1', 'managed_h1') else ('h2',))
        require(case.get('alpn') in allowed, 'wrong scenario protocol/ALPN')
        require(case['client'] != 'h3' or case['tls'] == 'TLSv1.3', 'QUIC requires TLS1.3')
        url = case.get('url', '')
        scheme = 'wss://' if case['client'] == 'wss' else 'https://'
        require(isinstance(url, str) and url.startswith(scheme) and url.count('{port}') == 1
                and not any(ord(char) <= 32 or ord(char) == 127 for char in url),
                'verified peer URL with one port placeholder required')
        parsed = urlsplit(url.replace('{port}', '1'))
        allowed_netlocs = {'localhost:1'}
        if case['client'] in ('managed_h1', 'managed_h2') and case['action'] == 'invalid_identity':
            # The consumer pins this reserved invalid origin to its owned loopback peer.
            allowed_netlocs.add('wrong.invalid:1')
        require(parsed.netloc in allowed_netlocs and not parsed.fragment and
                '{' not in parsed.path + parsed.query and '}' not in parsed.path + parsed.query,
                'owned peer route without credentials/fragment required')
        needs_gate = (case['action'] == 'cancellation' and case['client'] in
                      ('h1', 'h2', 'managed_h1', 'managed_h2')) or (
                          case['client'] == 'h3' and case['action'] in
                          ('timeout', 'cancellation', 'shutdown'))
        if needs_gate:
            path = case.get('gate_file')
            require(isinstance(path, str) and path.startswith('{run}/') and
                    '..' not in Path(path).parts and path.count('{run}') == 1 and
                    '{' not in path[6:] and '}' not in path[6:],
                    'independent per-scenario gate file beneath fresh run directory required')
        require(isinstance(case.get('ca_file'), str) and case['ca_file'], 'explicit captured peer CA required')
        require(type(case.get('timeout_ms')) is int and 1 <= case['timeout_ms'] <= 30_000,
                'finite scenario timeout in 1..30000ms required')
        require(isinstance(case.get('expected'), str), 'exact expected payload required')
    require(seen == REQUIRED, 'mandatory scenario missing')
    return plan


def project_source(version):
    validate_version(version)
    dependencies = ', '.join('{:' + package + ', "== ' + version + '"}' for package in PACKAGES)
    return f'''defmodule NoOTP.ConsumerProject do
  use Mix.Project
  def project do
    [app: :no_otp_consumer, version: "0.0.0", deps: [{dependencies}],
     releases: [no_otp_consumer: [include_erts: true, strip_beams: false]]]
  end
  def application, do: [extra_applications: [:logger, :public_key]]
end
'''


def production_environment(directory, inherited):
    env = dict(inherited)
    for key in tuple(env):
        if key.startswith(('RELEASE_', 'ERL_')):
            env.pop(key)
    for key in ('ERL_LIBS', 'ERL_FLAGS', 'ERL_AFLAGS', 'ERL_ZFLAGS', 'ELIXIR_ERL_OPTIONS',
                'MIX_BUILD_PATH', 'MIX_DEPS_PATH', 'MIX_ENV', 'MIX_TARGET', 'MIX_EXS',
                'HEX_HOME', 'HEX_MIRROR', 'HEX_TRUSTED_MIRROR', 'HEX_UNSAFE_REGISTRY',
                'HEX_UNSAFE_HTTPS', 'HTTP_FETCH_CI_APP', 'RELEASE_ROOT', 'RELEASE_COOKIE',
                'RELEASE_DISTRIBUTION', 'RELEASE_NODE'):
        env.pop(key, None)
    env.update(MIX_ENV='prod', MIX_BUILD_PATH=str(directory / 'build'),
               MIX_DEPS_PATH=str(directory / 'deps'), HEX_HOME=str(directory / 'hex'),
               PYTHONDONTWRITEBYTECODE='1')
    return env


def within(path, root):
    return Path(path).is_absolute() and Path(os.path.normpath(path)).is_relative_to(
        Path(os.path.normpath(root)))


def validate_runtime(state, release):
    require(isinstance(state, dict), 'runtime isolation evidence missing')
    for key in ('ssl_available', 'ssl_loaded', 'ssl_application_loaded', 'ssl_started'):
        require(state.get(key) is False, f'{key}: OTP ssl unavailable/not-loaded/not-started must be proved')
    paths = state.get('code_paths')
    require(isinstance(paths, list) and paths, 'actual release code paths required')
    modules = state.get('loaded_modules')
    require(isinstance(modules, dict) and set(MODULES).issubset(modules), 'all representative loaded module paths required')
    all_loaded = state.get('all_loaded_paths')
    require(isinstance(all_loaded, dict) and all_loaded, 'complete loaded production module inventory required')
    state['canonical_paths'] = {}
    state['canonical_errors'] = {}
    try:
        canonical_release = release.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        state['canonical_errors'][str(release)] = str(error)
        raise GateError('canonical release path unconfirmed') from error
    state['canonical_release'] = str(canonical_release)
    require(str(canonical_release) == str(release), 'canonical release root escaped owned directory')
    for path in paths + list(modules.values()) + list(all_loaded.values()):
        require(isinstance(path, str) and within(path, release), 'host/umbrella module path escaped release')
        try:
            canonical = str(Path(path).resolve(strict=True))
        except (OSError, RuntimeError) as error:
            state['canonical_errors'][path] = str(error)
            raise GateError('canonical module path unconfirmed') from error
        state['canonical_paths'][path] = canonical
        require(within(canonical, canonical_release), 'canonical module path escaped owned release')
        require(not any(part in ('test', 'support', '_build', 'deps') or
                        part.startswith('ssl-') for part in Path(path).parts + Path(canonical).parts),
                'OTP ssl or test support on production code path')


def validate_callable_preflight(report):
    """Incoming-only diagnostics cannot authorize any external classification."""
    require(report.get('external_callable_records', []) == [],
            'external callable classification is not implemented')
    preflight = report.get('callable_provenance_preflight')
    inspections = report.get('beam_inspections', [])
    require(isinstance(inspections, list), 'BEAM inspection inventory malformed')
    for inspection in inspections:
        require(isinstance(inspection, dict) and
                inspection.get('external_callable_records', []) == [],
                'per-BEAM external callable classification is not implemented')
    if preflight is None:
        return
    require(isinstance(preflight, dict) and preflight.get('schema') == 1 and
            type(preflight.get('schema')) is int and preflight.get('stage') == 'incoming_only',
            'unsupported callable provenance stage')
    require(preflight.get('external_callable_records') == [],
            'incoming diagnostics cannot classify callable origins')
    for key in ('requests_valid', 'scan_complete'):
        require(type(preflight.get(key)) is bool, 'callable completeness flag malformed')
    for key, limit in (('scanned_nodes', 2_000_001), ('scanned_sites', 100_000)):
        require(type(preflight.get(key)) is int and 0 <= preflight[key] <= limit,
                'callable scan bound malformed')
    require(not preflight['scan_complete'] or
            (preflight['scanned_nodes'] <= 2_000_000 and preflight['scanned_sites'] < 100_000),
            'exhausted callable scan claimed complete')
    snapshots = preflight.get('snapshots')
    require(isinstance(snapshots, list) and
            len(snapshots) == len(inspections) == report.get('checked_beams'),
            'callable snapshot coverage mismatch')
    by_beam = {}
    by_module = {}
    inspected = {item.get('beam'): item for item in inspections}
    require(len(inspected) == len(inspections), 'duplicate inspected BEAM identity')
    for snapshot in snapshots:
        require(isinstance(snapshot, dict), 'callable snapshot malformed')
        beam, module, sha = (snapshot.get(key) for key in ('beam', 'module', 'sha256'))
        require(isinstance(beam, str) and beam and isinstance(module, str) and module and
                isinstance(sha, str) and re.fullmatch(r'[0-9a-f]{64}', sha) is not None,
                'callable snapshot identity malformed')
        require(beam not in by_beam and module not in by_module and beam in inspected,
                'duplicate or uninspected callable snapshot')
        require(all(snapshot.get(key) == inspected[beam].get(key)
                    for key in ('beam', 'module', 'sha256')),
                'stale callable snapshot')
        require(type(snapshot.get('selected')) is bool and type(snapshot.get('debug')) is bool,
                'callable artifact selection evidence malformed')
        require(type(inspected[beam].get('missing_abstract_code')) is bool and
                snapshot['debug'] != inspected[beam]['missing_abstract_code'],
                'callable debug evidence mismatch')
        exports = snapshot.get('exports')
        require(isinstance(exports, list), 'callable export inventory missing')
        exported = set()
        for export in exports:
            require(isinstance(export, dict) and isinstance(export.get('function'), str) and
                    export['function'] and type(export.get('arity')) is int and
                    0 <= export['arity'] <= 255, 'callable export malformed')
            identity = (export['function'], export['arity'])
            require(identity not in exported, 'duplicate callable export')
            exported.add(identity)
        by_beam[beam] = snapshot
        by_module[module] = exported
    roots = preflight.get('roots')
    require(isinstance(roots, list) and len(roots) <= 64 and
            (preflight['requests_valid'] or roots == []), 'callable request inventory malformed')
    roots_seen = set()
    node_identities = {}
    for entry in roots:
        require(isinstance(entry, dict) and isinstance(entry.get('root'), dict),
                'callable root malformed')
        root = entry['root']
        require(isinstance(root.get('module'), str) and root['module'] and
                isinstance(root.get('function'), str) and root['function'] and
                type(root.get('arity')) is int and 0 <= root['arity'] <= 255,
                'callable root identity malformed')
        identity = (root['module'], root['function'], root['arity'])
        require(identity not in roots_seen, 'duplicate callable root')
        roots_seen.add(identity)
        exported = (root['function'], root['arity']) in by_module.get(root['module'], set())
        require(type(entry.get('exported')) is bool and entry['exported'] == exported,
                'callable root export mismatch')
        incoming = entry.get('incoming')
        require(isinstance(incoming, list) and len(incoming) <= preflight['scanned_sites'],
                'callable incoming coverage malformed')
        nodes_seen = set()
        for edge in incoming:
            require(isinstance(edge, dict), 'callable edge malformed')
            beam, path, ordinal = (edge.get(key) for key in ('beam', 'path', 'ordinal'))
            require(isinstance(beam, str) and beam in by_beam and
                    edge.get('module') == by_beam[beam]['module'], 'unbound callable edge BEAM')
            require(isinstance(path, list) and path and
                    all(type(index) is int and index >= 0 for index in path),
                    'callable original-node path malformed')
            require(type(ordinal) is int and 0 <= ordinal < preflight['scanned_sites'] and
                    type(edge.get('line')) is int and edge['line'] >= 0,
                    'callable original-node ordinal malformed')
            owner = edge.get('owner')
            require(isinstance(owner, dict) and isinstance(owner.get('function'), str) and
                    owner['function'] and type(owner.get('arity')) is int and
                    0 <= owner['arity'] <= 255, 'callable owner malformed')
            require(edge.get('kind') in {
                'capture', 'capture_invocation', 'apply', 'direct_arguments_require_proof',
                'dynamic_target_requires_proof', 'metadispatch_requires_proof',
                'metadispatch_capture_requires_proof', 'unknown_callable_arity',
                'callable_or_metadispatch_requires_proof', 'callable_target_requires_proof'},
                'unknown callable edge derivation')
            node = (beam, tuple(path))
            require(node not in nodes_seen, 'duplicate callable incoming node')
            nodes_seen.add(node)
            bound = (beam, tuple(path), edge['module'], owner['function'], owner['arity'], edge['line'])
            require(ordinal not in node_identities or node_identities[ordinal] == bound,
                    'callable node ordinal rebound')
            node_identities[ordinal] = bound
        closed = (preflight['scan_complete'] and exported and not incoming and
                  all(item['selected'] and item['debug'] for item in snapshots))
        require(entry.get('status') == ('no_syntactic_incoming_edges' if closed else 'unconfirmed'),
                'callable incoming status disagrees with evidence')

    validate_private_shapes(preflight, by_beam, by_module, node_identities)


def validate_private_shapes(preflight, by_beam, by_module, node_identities):
    proof = preflight.get('private_shape_derivations')
    if proof is None:
        return
    require(isinstance(proof, dict) and type(proof.get('schema')) is int and
            proof['schema'] == 1 and type(proof.get('requests_valid')) is bool,
            'private shape schema malformed')
    modules = proof.get('modules')
    require(isinstance(modules, list) and len(modules) <= 64 and
            (proof['requests_valid'] or not modules), 'private shape requests malformed')
    seen_modules = set()
    paths = {(bound[0], bound[1]): ordinal for ordinal, bound in node_identities.items()}

    def slot(value):
        require(isinstance(value, dict) and isinstance(value.get('function'), str) and
                value['function'] and type(value.get('arity')) is int and
                1 <= value['arity'] <= 255 and type(value.get('parameter_index')) is int and
                0 <= value['parameter_index'] < value['arity'], 'private shape slot malformed')
        return (value['function'], value['arity'], value['parameter_index'])

    def shapes(values):
        require(isinstance(values, list) and 0 < len(values) <= 16,
                'private shape domain malformed')
        result = set()
        for value in values:
            require(isinstance(value, dict), 'private shape value malformed')
            if value.get('kind') == 'atom':
                require(set(value) == {'kind', 'value'} and isinstance(value['value'], str),
                        'private atom shape malformed')
                key = ('atom', value['value'])
            else:
                require(set(value) == {'kind', 'tag', 'arity'} and value['kind'] == 'tuple' and
                        isinstance(value['tag'], str) and type(value['arity']) is int and
                        1 <= value['arity'] <= 255, 'private tuple shape malformed')
                key = ('tuple', value['tag'], value['arity'])
            require(key not in result, 'duplicate private shape')
            result.add(key)
        return result

    def site(value, record):
        require(isinstance(value, dict) and value.get('beam') == record['beam'] and
                value.get('module') == record['module'], 'unbound private shape occurrence')
        path, ordinal, owner = (value.get(key) for key in ('path', 'ordinal', 'owner'))
        require(isinstance(path, list) and path and len(path) <= 100_000 and
                all(type(index) is int and index >= 0 for index in path) and
                type(ordinal) is int and 0 <= ordinal < preflight['scanned_sites'] and
                type(value.get('line')) is int and value['line'] >= 0,
                'private shape original occurrence malformed')
        require(isinstance(owner, dict) and isinstance(owner.get('function'), str) and
                owner['function'] and type(owner.get('arity')) is int and
                0 <= owner['arity'] <= 255, 'private shape owner malformed')
        bound = (record['beam'], tuple(path), record['module'], owner['function'],
                 owner['arity'], value['line'])
        require(ordinal not in node_identities or node_identities[ordinal] == bound,
                'private shape ordinal rebound')
        position = (record['beam'], tuple(path))
        require(position not in paths or paths[position] == ordinal,
                'private shape path rebound')
        node_identities[ordinal] = bound
        paths[position] = ordinal
        return (owner['function'], owner['arity']), ordinal

    for record in modules:
        require(isinstance(record, dict) and isinstance(record.get('module'), str) and
                record['module'] and record['module'] not in seen_modules,
                'duplicate or malformed private shape module')
        seen_modules.add(record['module'])
        require(record.get('beam') is None or isinstance(record.get('beam'), str),
                'private shape BEAM path malformed')
        snapshot = by_beam.get(record.get('beam'))
        require((snapshot is None and record.get('beam') is None and
                 record.get('sha256') is None and record['module'] not in by_module) or
                (snapshot is not None and snapshot['module'] == record['module'] and
                 snapshot['sha256'] == record.get('sha256')), 'stale private shape artifact')
        require(record.get('status') in ('checked', 'unconfirmed'), 'private shape status malformed')
        if record['status'] == 'unconfirmed':
            require(record.get('inventory') is None and record.get('slots') == [] and
                    record.get('callers') == [] and record.get('observations') == [],
                    'unconfirmed shape contains a certificate')
            continue
        require(snapshot is not None and proof['requests_valid'] and preflight['scan_complete'] and
                all(item['selected'] and item['debug'] for item in by_beam.values()),
                'private shape lacks complete selected artifacts')
        inventory = record.get('inventory')
        require(isinstance(inventory, dict) and inventory.get('complete') is True and
                type(inventory.get('nodes')) is int and 0 < inventory['nodes'] <= 100_000 and
                type(inventory.get('calls')) is int and 0 < inventory['calls'] <= 4_096,
                'private shape caller inventory incomplete')
        entries = record.get('slots')
        require(isinstance(entries, list) and 0 < len(entries) <= 256, 'private shape slots missing')
        domains = {}
        for entry in entries:
            key = slot(entry)
            require(key not in domains and key[:2] not in by_module[record['module']],
                    'duplicate or exported private shape slot')
            domains[key] = shapes(entry.get('shapes'))
        callers = record.get('callers')
        require(isinstance(callers, list) and callers and
                len(callers) <= inventory['calls'] * len(domains), 'private shape callers missing')
        origins = {key: [] for key in domains}
        seen_calls = set()
        for call in callers:
            require(isinstance(call, dict), 'private shape caller malformed')
            target = slot(call.get('target'))
            require(target in domains, 'private shape caller target absent')
            owner, ordinal = site(call.get('site'), record)
            require((ordinal, target) not in seen_calls, 'duplicate private shape caller')
            seen_calls.add((ordinal, target))
            origin = call.get('origin')
            require(isinstance(origin, dict), 'private shape origin malformed')
            if origin.get('kind') == 'seed':
                require(shapes([origin.get('shape')]) <= domains[target] and
                        owner not in {key[:2] for key in domains}, 'private shape seed unproved')
                origins[target].append(None)
            else:
                require(origin.get('kind') == 'parameter', 'unknown private shape origin')
                source = slot(origin.get('source'))
                require(source in domains and source[:2] == owner and
                        domains[source] <= domains[target], 'private shape forwarding unproved')
                origins[target].append(source)
        require(all(origins.values()), 'private shape caller coverage missing')
        reached = set()
        while len(reached) < len(domains):
            ready = {key for key, values in origins.items() if key not in reached and
                     any(value is None or value in reached for value in values)}
            require(ready, 'private shape cycle lacks an external seed')
            reached.update(ready)
        observations = record.get('observations')
        require(isinstance(observations, list) and 0 < len(observations) <= 64,
                'private shape observations missing')
        seen_observations = set()
        for observation in observations:
            require(isinstance(observation, dict), 'private shape observation malformed')
            source = slot(observation.get('source'))
            require(source in domains, 'private shape observation source absent')
            owner, ordinal = site(observation.get('site'), record)
            callee = observation.get('callee')
            require(isinstance(callee, dict) and isinstance(callee.get('function'), str) and
                    callee['function'] and type(callee.get('arity')) is int and
                    1 <= callee['arity'] <= 255 and type(callee.get('argument_index')) is int and
                    0 <= callee['argument_index'] < callee['arity'],
                    'private shape observation callee malformed')
            key = (ordinal, callee['argument_index'])
            require(key not in seen_observations and owner == source[:2] and
                    shapes(observation.get('shapes')) == domains[source],
                    'private shape observation domain or occurrence mismatch')
            seen_observations.add(key)
            expected = observation.get('expected_path')
            require(expected is None or
                    (isinstance(expected, list) and expected and
                     all(type(index) is int and index >= 0 for index in expected) and
                     expected == observation['site']['path']), 'stale private shape observation path')


def validate_private_fields(report):
    """Auxiliary map facts do not discharge dispatch or classify external code."""
    proof = report.get('private_field_derivations')
    if proof is None:
        return
    require(isinstance(proof, dict) and type(proof.get('schema')) is int and
            proof['schema'] == 1 and proof.get('stage') == 'diagnostic_only' and
            type(proof.get('requests_valid')) is bool and
            proof.get('external_callable_records', []) == [], 'private field schema malformed')
    modules = proof.get('modules')
    require(isinstance(modules, list) and len(modules) <= 64 and
            (proof['requests_valid'] or not modules), 'private field requests malformed')
    inspections = report.get('beam_inspections', [])
    by_module = {item['module']: item for item in inspections}
    seen = set()

    def owner(value):
        require(isinstance(value, dict) and isinstance(value.get('function'), str) and
                value['function'] and type(value.get('arity')) is int and
                0 <= value['arity'] <= 255, 'private field owner malformed')
        return value['function'], value['arity']

    def slot(value):
        name, arity = owner(value)
        require(type(value.get('parameter_index')) is int and
                0 <= value['parameter_index'] < arity and
                isinstance(value.get('field'), str), 'private field slot malformed')
        return name, arity, value['parameter_index'], value['field']

    def targets(value):
        require(isinstance(value, list) and 0 < len(value) <= 16 and
                all(isinstance(item, str) for item in value) and
                value == sorted(set(value)), 'private field finite targets malformed')
        return set(value)

    def path(value):
        require(isinstance(value, list) and 0 < len(value) <= 100_000 and
                all(type(item) is int and item >= 0 for item in value),
                'private field occurrence path malformed')
        return tuple(value)

    def site(value):
        require(isinstance(value, dict) and type(value.get('line')) is int and
                value['line'] >= 0, 'private field occurrence malformed')
        return owner(value.get('owner')), path(value.get('path'))

    for record in modules:
        require(isinstance(record, dict) and isinstance(record.get('module'), str) and
                record['module'] not in seen and type(record.get('selected')) is bool and
                record.get('status') in ('checked', 'unconfirmed') and
                record.get('external_callable_records', []) == [], 'private field module malformed')
        seen.add(record['module'])
        inspection = by_module.get(record['module'])
        require((inspection is None and record.get('beam') is None and
                 record.get('sha256') is None) or
                (inspection is not None and record.get('beam') == inspection.get('beam') and
                 record.get('sha256') == inspection.get('sha256')),
                'stale private field artifact')
        inventory = record.get('inventory')
        if inventory is None:
            require(record['status'] == 'unconfirmed' and record['selected'] is False and
                    all(record.get(key) == [] for key in
                        ('slots', 'callers', 'constructions', 'conditional_returns')),
                    'unconfirmed field inventory contains a certificate')
            continue
        require(record['selected'] is True and inspection is not None and
                inspection.get('missing_abstract_code') is False and isinstance(inventory, dict) and
                type(inventory.get('complete')) is bool, 'private field selection unconfirmed')
        for key, bound in (('nodes', 100_000), ('calls', 4_096), ('evaluated_nodes', 200_002)):
            require(type(inventory.get(key)) is int and 0 <= inventory[key] <= bound,
                    'private field inventory bound malformed')
        require(not inventory['complete'] or inventory['evaluated_nodes'] <= 200_000,
                'exhausted field evaluator claimed complete')
        requested = record.get('slots')
        require(isinstance(requested, list) and 0 < len(requested) <= 256,
                'private field slot inventory malformed')
        domains = {}
        for item in requested:
            identity = slot(item)
            require(identity not in domains, 'duplicate private field slot')
            domains[identity] = targets(item.get('targets'))
        candidates = {item[:2] for item in domains}
        scalars = {}
        scalar_proof = inspection.get('parameter_invariant_derivation', {})
        for item in scalar_proof.get('checked_slots', []) if scalar_proof.get('status') == 'checked' else []:
            scalars[(item['function'], item['arity'], item['parameter_index'])] = set(item['targets'])

        def value(fact, depth=0):
            require(isinstance(fact, dict) and depth <= 256, 'private field value malformed')
            kind = fact.get('kind')
            if kind == 'unknown':
                require(set(fact) == {'kind'}, 'unknown field value has asserted facts')
            elif kind == 'atoms':
                atoms = targets(fact.get('targets'))
                origins = fact.get('origins')
                require(isinstance(origins, list) and 0 < len(origins) <= 16,
                        'private field value lacks origins')
                unique = set()
                for origin in origins:
                    require(isinstance(origin, dict), 'private field origin malformed')
                    source_kind = origin.get('kind')
                    if source_kind == 'field_identity':
                        source = slot(origin.get('source'))
                        require(source in domains and domains[source] <= atoms,
                                'unbound private field identity')
                        identity = source_kind, source
                    elif source_kind == 'checked_parameter':
                        source = origin.get('source')
                        source_owner = owner(source)
                        require(type(source.get('parameter_index')) is int,
                                'checked scalar parameter malformed')
                        source_slot = source_owner + (source['parameter_index'],)
                        require(source_slot in scalars and scalars[source_slot] <= atoms,
                                'private field borrowed an unchecked scalar request')
                        identity = source_kind, source_slot
                    else:
                        require(source_kind == 'literal', 'unsupported private field origin')
                        identity = source_kind, owner(origin.get('owner')), path(origin.get('path'))
                    require(identity not in unique, 'duplicate private field value origin')
                    unique.add(identity)
            elif kind == 'partial_map':
                fields = fact.get('fields')
                require(isinstance(fields, list), 'partial map field inventory malformed')
                names = set()
                for item in fields:
                    require(isinstance(item, dict) and isinstance(item.get('field'), str) and
                            item['field'] not in names and isinstance(item.get('value'), dict) and
                            item['value'].get('kind') == 'atoms', 'partial map contains non-flat facts')
                    names.add(item['field'])
                    value(item['value'], depth + 1)
            else:
                require(kind == 'tuple' and isinstance(fact.get('elements'), list),
                        'unsupported private field abstract value')
                for item in fact['elements']:
                    value(item, depth + 1)

        incoming = {identity: [] for identity in domains}
        callers = record.get('callers')
        require(isinstance(callers, list) and len(callers) <= 4_096 * 256,
                'private field incoming inventory malformed')
        occurrences = set()
        for call in callers:
            require(isinstance(call, dict), 'private field caller malformed')
            target = slot(call.get('target'))
            require(target in domains, 'unrequested private field target')
            source_owner, position = site(call.get('site'))
            occurrence = position, target
            require(occurrence not in occurrences, 'duplicate private field incoming occurrence')
            occurrences.add(occurrence)
            fact = call.get('fact')
            value(fact)
            origin = call.get('origin')
            require(isinstance(origin, dict), 'private field transfer origin malformed')
            kind = origin.get('kind')
            if kind == 'unknown':
                incoming[target].append(None)
                continue
            require(fact['kind'] == 'atoms' and targets(fact['targets']) <= domains[target],
                    'private field transfer violates domain')
            if kind == 'seed':
                require(source_owner not in candidates and
                        targets(origin.get('targets')) == targets(fact['targets']) and
                        all(item['kind'] in ('literal', 'checked_parameter') for item in fact['origins']),
                        'recursive replacement or unchecked field seed')
                incoming[target].append('seed')
            else:
                require(kind == 'field_identity', 'unsupported private field transfer')
                source = slot(origin.get('source'))
                require(source in domains and source[3] == target[3] and
                        domains[source] <= domains[target] and
                        fact['origins'] == [origin] and targets(fact['targets']) == domains[source],
                        'private field identity transfer mismatch')
                incoming[target].append(source)
        constructions = record.get('constructions')
        require(isinstance(constructions, list) and len(constructions) <= 100_000,
                'private field construction inventory malformed')
        for item in constructions:
            require(isinstance(item, dict), 'private field construction malformed')
            site(item.get('site'))
            value(item.get('value'))
        summaries = record.get('conditional_returns')
        require(isinstance(summaries, list) and len(summaries) == len(candidates),
                'private field conditional summaries incomplete')
        summarized = set()
        for summary in summaries:
            key = owner(summary)
            require(key in candidates and key not in summarized,
                    'duplicate or unrequested conditional field summary')
            summarized.add(key)
            value(summary.get('value'))
        reached = set()
        while True:
            ready = {identity for identity, origins in incoming.items()
                     if any(source == 'seed' or source in reached for source in origins)} - reached
            if not ready:
                break
            reached.update(ready)
        checked = (inventory['complete'] and reached == set(domains) and
                   all(origins and None not in origins for origins in incoming.values()))
        require(record['status'] == ('checked' if checked else 'unconfirmed'),
                'private field graph status disagrees with complete seeded origins')


def validate_artifacts(report, version):
    require(isinstance(report, dict), 'artifact audit missing')
    validate_callable_preflight(report)
    validate_private_fields(report)
    for field in ('checked_app_files', 'checked_rel_files', 'checked_boot_files', 'checked_beams'):
        require(type(report.get(field)) is int and report[field] > 0, f'{field}: no artifacts inspected')
    for field in ('ssl_app_dependencies', 'ssl_bundle_paths', 'ssl_boot_entries',
                  'direct_otp_ssl_imports', 'unresolved_dispatch', 'missing_abstract_code',
                  'duplicate_package_apps'):
        require(report.get(field) == [], f'{field}: forbidden or unconfirmed production evidence')
    require(report.get('package_versions') == {package: version for package in PACKAGES},
            'all nine release package versions must match candidate archives')


def validate_scenario(case, consumer, peer, nonce):
    count = 0 if case['action'] == 'invalid_identity' else 1
    for origin, record in (('consumer', consumer), ('peer', peer)):
        require(isinstance(record, dict), f'{origin}: missing scenario')
        for key in ('id', 'client', 'action'):
            require(record.get(key) == case[key], f'{origin}: wrong {key}')
        require(record.get('nonce') == nonce, f'{origin}: stale scenario generation')
        require(record.get('result') == 'PASS' and type(record.get('executed')) is int
                and record['executed'] == 1, f'{origin}: skipped/zero/failed scenario')
        require(isinstance(record.get('peer_identity'), str) and record['peer_identity'],
                f'{origin}: independent peer identity missing')
    require(consumer['peer_identity'] == peer['peer_identity'], 'consumer/peer identity mismatch')
    require(consumer.get('requested_tls') == case['tls'] and consumer.get('required_alpn') == case['alpn'],
            'consumer requested policy mismatch')
    require(consumer.get('fallback_isolated') is True and consumer.get('requests_submitted') == 1,
            'consumer actual isolation/submission evidence missing')
    require(peer.get('tls') == case['tls'] and peer.get('alpn') == case['alpn'],
            'peer actual TLS/ALPN mismatch')
    require(peer.get('fallback') is False and peer.get('replay') is False,
            'independent peer fallback/replay evidence missing or failed')
    require(type(peer.get('requests')) is int and peer['requests'] == count,
            'wrong independent traffic count')
    require(consumer.get('cleanup') == 'confirmed', 'provider cleanup pending/unconfirmed/unsupported')
    allowed = {'request_completion', 'client_completion', 'managed_receipt', 'quic_session_endpoint'}
    require(consumer.get('cleanup_kind') in allowed, 'logical close/PID DOWN is not provider cleanup proof')
    expected_kind = ('quic_session_endpoint' if case['client'] == 'h3' else
                     'managed_receipt' if case['client'].startswith('managed_') else
                     'client_completion' if case['client'] in ('wss', 'sse') else 'request_completion')
    require(consumer['cleanup_kind'] == expected_kind, 'cleanup barrier belongs to a different client/resource scope')


class Runner:
    """Every command owns one new session; only that group is stopped/reaped."""

    def __init__(self, directory, max_seconds=1800):
        self.directory = directory
        self.deadline = time.monotonic() + max_seconds
        self.commands = []

    def remaining(self, limit=300):
        left = min(limit, self.deadline - time.monotonic())
        require(left > 0, 'whole gate deadline exceeded')
        return left

    @staticmethod
    def stop(process):
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                return process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        return process.communicate(timeout=5)

    def command(self, args, *, cwd=None, env=None, limit=300):
        started = time.monotonic()
        entry = dict(argv=list(map(str, args)), cwd=str(cwd), exit=None)
        self.commands.append(entry)
        process = subprocess.Popen(entry['argv'], cwd=cwd, env=env, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, start_new_session=True)
        try:
            output, _ = process.communicate(timeout=self.remaining(limit))
        except BaseException:
            output, _ = self.stop(process)
            entry.update(exit=process.returncode, timeout_or_interrupt=True)
            raise GateError('owned command interrupted or exceeded deadline') from None
        finally:
            entry['elapsed_seconds'] = time.monotonic() - started
            self.directory.joinpath(f'command-{len(self.commands):03d}.log').write_text(
                locals().get('output', 'output unavailable'))
            self.directory.joinpath('commands.json').write_text(json.dumps(self.commands, indent=2))
        entry['exit'] = process.returncode
        self.directory.joinpath('commands.json').write_text(json.dumps(self.commands, indent=2))
        require(process.returncode == 0, f'owned command failed: exit={process.returncode}')
        return output


def build_release(project, release, env, runner):
    runner.command(['unbuffer', 'mix', 'deps.get'], cwd=project, env=env)
    runner.command(['unbuffer', 'mix', 'compile', '--warnings-as-errors'], cwd=project, env=env)
    runner.command(['unbuffer', 'mix', 'run', '--no-start', '-e', PROVENANCE], cwd=project, env=env)
    runner.command(['unbuffer', 'mix', 'release', 'no_otp_consumer', '--path', str(release)],
                   cwd=project, env=env)


def release_command(release):
    return [str(release / 'bin/no_otp_consumer'), 'eval', 'NoOTP.Consumer.run()']


def verify_source(stage, source, archives, version):
    """Reuse archive audit, then bind portable staged bytes to actual source bytes."""
    pinned = {}
    for package in PACKAGES:
        archive_audit.audit_package(package, version, stage, archives)
        archive = archives / f'{package}-{version}.tar'
        with tarfile.open(archive) as outer:
            content = outer.extractfile('contents.tar.gz').read()
        with tarfile.open(fileobj=io.BytesIO(content), mode='r:gz') as inner:
            members = inner.getmembers()
            require(all(member.isfile() or member.isdir() for member in members),
                    'archive links/devices have no safe source provenance')
            names = sorted(member.name for member in members if member.isfile())
        for name in names:
            relative = Path(name)
            require(not relative.is_absolute() and '..' not in relative.parts, 'archive path escaped stage')
            path = stage / package / relative
            original = source / 'apps' / package / relative
            require(original.is_file(), f'staged file lacks source provenance: {package}/{relative}')
            wanted = portable_manifest(original.read_text()).encode() if relative == Path('mix.exs') else original.read_bytes()
            require(path.read_bytes() == wanted, f'staged source differs: {package}/{relative}')
            pinned[f'{package}/{relative}'] = hashlib.sha256(wanted).hexdigest()
    return pinned


class Peer:
    def __init__(self, name, config, directory, env, runner):
        self.name, self.config, self.directory, self.runner = name, config, directory, runner
        script = Path(config['script']).resolve()
        require(hashlib.sha256(script.read_bytes()).hexdigest() == config['sha256'], 'external peer script pin changed')
        self.records, self.lines, self.messages = [], [], queue.Queue()
        argv = [arg.replace('{run}', str(directory)) for arg in config['argv']]
        self.process = subprocess.Popen(argv, cwd=directory, env=env, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        text=True, start_new_session=True, bufsize=1)
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()
        try:
            ready = self.messages.get(timeout=runner.remaining(15))
            if config.get('kind') == 'http3' and isinstance(ready, int):
                ready = dict(port=ready, identity=config['sha256'])
            require(isinstance(ready, dict) and (ready.get('kind') == 'ready' or ready.get('event') == 'ready'
                    or config.get('kind') == 'http3'), 'peer readiness missing')
            require(type(ready.get('port')) is int and 0 < ready['port'] < 65536, 'peer port invalid')
            self.ready = ready
        except BaseException:
            self.close()
            raise

    def _read(self):
        for line in self.process.stdout:
            if len(line) > 1_048_576 or len(self.lines) >= 10_000:
                self.messages.put(dict(peer_error='peer output bound exceeded'))
                break
            self.lines.append(line)
            try:
                record = json.loads(line)
                self.records.append(record)
                self.messages.put(record)
            except json.JSONDecodeError:
                self.messages.put(dict(peer_error='non-JSON peer output'))

    def observe(self):
        if self.config.get('kind', 'structured') in ('structured', 'performance'):
            require(self.process.poll() is None, 'external peer exited before evidence collection')
            self.process.stdin.write('{"command":"stats"}\n')
            self.process.stdin.flush()
            until = time.monotonic() + self.runner.remaining(15)
            while time.monotonic() < until:
                try:
                    record = self.messages.get(timeout=max(0.001, until - time.monotonic()))
                except queue.Empty:
                    break
                if isinstance(record, dict) and record.get('event', record.get('kind')) == 'stats':
                    require(record.get('errors') == [] and record.get('active_connections') == 0,
                            'peer error or live connections remain after release traffic')
                    require(not any(isinstance(item, dict) and ('peer_error' in item or item.get('kind') == 'error')
                                    for item in self.records), 'external peer reported failure')
                    return
            raise GateError('external peer stats deadline/evidence missing')

    def scenario(self, case, nonce):
        # Structured records are independently emitted, not supplied by consumer.
        selected = [record for record in self.records if isinstance(record, dict)
                    and record.get('kind') == 'scenario' and record.get('id') == case['id']]
        require(len(selected) == 1, f'{case["id"]}: missing exact peer scenario evidence; raw peer adapter is diagnostic only')
        return selected[0]

    def close(self):
        if self.process.poll() is None:
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=5)
        else:
            self.process.wait(timeout=5)
        self.thread.join(timeout=5)
        self.directory.joinpath(f'peer-{self.name}.log').write_text(''.join(self.lines))
        self.directory.joinpath(f'peer-{self.name}.json').write_text(json.dumps(self.records, indent=2))
        require(not self.thread.is_alive(), 'owned peer output reader did not stop')


@contextmanager
def bounded_registry_commands(runner, source=None):
    original = consumer_gate.command
    original_root = consumer_gate.ROOT
    consumer_gate.command = runner.command
    if source is not None:
        consumer_gate.ROOT = source
    try:
        yield
    finally:
        consumer_gate.command = original
        consumer_gate.ROOT = original_root


def run(version, archives, stage, source, source_sha, plan, output, max_seconds=1800, *, published=False):
    validate_version(version)
    validate_plan(plan)
    require(re.fullmatch(r'[a-f0-9]{40}', source_sha), 'full source SHA required')
    output, source = output.resolve(), source.resolve()
    require(not output.exists() and not within(output, source), 'new isolated output outside source tree required')
    output.mkdir(parents=True)
    runner = Runner(output, max_seconds)
    nonce = uuid.uuid4().hex
    project, release = output / 'project', output / 'release'
    env = production_environment(project, os.environ)
    if published:
        env.pop('HEX_OFFLINE', None)
        env.update(HEX_CONFIG_HOME=str(project / 'hex'), HEX_CACHE_HOME=str(project / 'hex-cache'))
    peers = []
    report = dict(gate='no_otp_production_release', status='FAIL', nonce=nonce,
                  source_sha=source_sha, version=version, output=str(output),
                  dependency_source='published' if published else 'candidate')
    try:
        head = runner.command(['git', 'rev-parse', 'HEAD'], cwd=source, env=env).strip()
        require(head == source_sha, 'candidate source HEAD mismatch')
        runner.command(['unbuffer', 'elixir', str(source / 'scripts/release/versions.exs'),
                        'validate', version], cwd=source, env=env)
        runner.command(['unbuffer', 'elixir', str(source / 'scripts/release/archives.exs'),
                        version, str(archives)], cwd=source, env=env)
        report['staged_source_sha256'] = verify_source(stage, source, archives, version)
        report['archives'] = {package: hashlib.sha256(
            (archives / f'{package}-{version}.tar').read_bytes()).hexdigest() for package in PACKAGES}
        if published:
            statuses = runner.command([sys.executable, str(source / 'scripts/release/hex_packages.py'),
                                       'preflight', version, str(archives)], cwd=source, env=env)
            require(statuses.strip().splitlines() == [f'{package}: matching' for package in PACKAGES],
                    'all nine published archives must match before release construction')
            report['published_archives'] = {package: 'matching' for package in PACKAGES}
        project.joinpath('lib').mkdir(parents=True)
        project.joinpath('mix.exs').write_text(project_source(version))
        for stem in ('no_otp_consumer', 'no_otp_release_audit'):
            shutil.copyfile(HERE / f'{stem}.exs', project / 'lib' / f'{stem}.ex')
        env.update(NO_OTP_VERSION=version, NO_OTP_PROJECT=str(project), NO_OTP_NONCE=nonce,
                   NO_OTP_RELEASE=str(release), NO_OTP_REPORT=str(output / 'release-report.json'))
        # Public CA input only: peer private keys are never read/copied by the gate.
        config = dict(schema=1, nonce=nonce, version=version, scenarios=[])
        with bounded_registry_commands(runner, source):
            registry = nullcontext(None)
            if not published:
                public = consumer_gate.setup_registry(archives, version, output / 'registry', env)
                registry = consumer_gate.local_registry(public)
            with registry as url:
                if url is not None:
                    runner.command(['unbuffer', 'mix', 'hex.repo', 'set', 'hexpm', '--url', url,
                                    '--public-key', str(public / 'public_key')], env=env)
                build_release(project, release, env, runner)
        for name, peer_config in plan['peers'].items():
            peers.append(Peer(name, peer_config, output, env, runner))
        by_name = {peer.name: peer for peer in peers}
        for case in plan['scenarios']:
            actual = dict(case)
            peer = by_name[case['peer']]
            actual['url'] = case['url'].replace('{port}', str(peer.ready['port']))
            actual['peer_identity'] = peer.ready.get('identity', peer.config['sha256'])
            actual['nonce'] = nonce
            ca = output / f'ca-{case["peer"]}.pem'
            ca.write_bytes(Path(case['ca_file']).read_bytes())
            actual['ca_file'] = str(ca)
            if 'gate_file' in case:
                actual['gate_file'] = case['gate_file'].replace('{run}', str(output))
            config['scenarios'].append(actual)
        config_path = output / 'traffic.json'
        config_path.write_text(json.dumps(config, indent=2))
        env['NO_OTP_CONFIG'] = str(config_path)
        runner.command(release_command(release), cwd=output, env=env, limit=runner.remaining(1200))
        actual = json.loads(Path(env['NO_OTP_REPORT']).read_text())
        report['release'] = actual
        validate_artifacts(actual.get('artifacts'), version)
        validate_runtime(actual.get('before'), release)
        validate_runtime(actual.get('after'), release)
        require(actual.get('runtime', {}).get('elixir') and actual['runtime'].get('otp'), 'runtime versions missing')
        require(len(actual.get('scenarios', [])) == len(REQUIRED), 'release scenario count missing')
        for peer in peers:
            peer.observe()
        for case in config['scenarios']:
            selected = [record for record in actual['scenarios'] if record.get('id') == case['id']]
            require(len(selected) == 1, 'release scenario duplicate/missing')
            validate_scenario(case, selected[0], by_name[case['peer']].scenario(case, nonce), nonce)
        report['status'] = 'PASS'
    except BaseException as error:
        report['error'] = str(error)
        raise
    finally:
        failures = []
        for peer in reversed(peers):
            try:
                peer.close()
            except BaseException as error:
                failures.append(str(error))
        report['teardown_errors'] = failures
        if failures:
            report['status'] = 'FAIL'
        output.joinpath('gate-report.json').write_text(json.dumps(report, indent=2))
        if failures:
            raise GateError('owned peer teardown failed; diagnostics retained')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('version')
    parser.add_argument('archives', type=Path)
    parser.add_argument('stage', type=Path)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--peer-plan', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--max-seconds', type=int, default=1800)
    parser.add_argument('--published', action='store_true')
    args = parser.parse_args()
    require(1 <= args.max_seconds <= 7200, 'bounded gate duration required')
    result = run(args.version, args.archives.resolve(), args.stage.resolve(), args.source_root,
                 args.source_sha, json.loads(args.peer_plan.read_text()), args.output, args.max_seconds,
                 published=args.published)
    print(json.dumps(dict(gate=result['gate'], status=result['status'], output=result['output'])))


if __name__ == '__main__':
    main()
