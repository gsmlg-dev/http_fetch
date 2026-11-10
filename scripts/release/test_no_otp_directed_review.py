"""Specific reviewed source and release binding, with adversarial receipt controls."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import no_otp_consumer_gate as gate
import no_otp_directed_review as review
from stage import PACKAGES

ROOT = Path(__file__).resolve().parents[2]


RENEWALS = ('1.0.0-rc.9', '1.0.0-rc.11')


def proof(group):
    return json.loads((ROOT / f'docs/no-otp-directed-{group}-proof.json').read_text())


def rewind(proof, version):
    """Undo each versioned renewal at or after `version`, newest first."""
    sites = proof['occurrences']
    for amendment in reversed(proof.get('source_review_amendments', [])):
        release = amendment.get('release_version')
        if release not in RENEWALS or RENEWALS.index(release) < RENEWALS.index(version):
            continue
        bindings = {item['inventory_occurrence']: item for item in amendment['occurrence_rebindings']}
        added = amendment.get('added_occurrences', [])
        sites = [site if site['inventory_occurrence'] not in bindings else
                 dict(site, line=bindings[site['inventory_occurrence']]['previous_line'],
                      mfa=bindings[site['inventory_occurrence']].get('previous_mfa', site['mfa']))
                 for site in sites if site['inventory_occurrence'] not in added]
    return sites


def historical_sites(proof):
    """Reconstruct the pre-Phase-1 identities for unchanged historical receipts."""
    return rewind(proof, '1.0.0-rc.9')


def identity_digest(sites):
    identities = sorted((site['module'].removeprefix(':'), site['line'], site['kind']) for site in sites)
    return len(identities), len(set(identities)), hashlib.sha256(
        json.dumps(identities, separators=(',', ':')).encode()).hexdigest()


def pto_amendment(quic):
    return next(item for item in quic['source_review_amendments']
                if item.get('purpose', '').startswith('PTO congestion-credit repair'))


class DirectedReviewTests(unittest.TestCase):
    def test_review_bundle_covers_all_original_sites_and_all_production_sources(self):
        bundle = review.load(ROOT, '1.0.0-rc.0', PACKAGES)
        self.assertEqual(len(bundle['occurrences']), 206)
        self.assertEqual(len([name for name in bundle['sources'] if name.split('/')[0] in PACKAGES]), 267)
        self.assertEqual(len(bundle['reviews']), 10)
        self.assertEqual(bundle['versions']['http_fetch'], '1.0.0-rc.0')

    def test_phase1_additions_and_moved_sites_match_current_production_inventory(self):
        bundle = review.load(ROOT, '1.0.0-rc.9', PACKAGES)
        http = json.loads((ROOT / 'docs/no-otp-directed-http-proof.json').read_text())
        amendment = next(item for item in http['source_review_amendments']
                         if item.get('release_version') == '1.0.0-rc.9')
        self.assertEqual(amendment['added_occurrences'], [178, 179, 180])
        sites = {site['inventory_occurrence']: site for site in http['occurrences']}
        self.assertEqual(sites[178]['mfa'], 'activate_owner/3')
        self.assertEqual(sites[178]['source'], 'apps/http_pool/lib/http/http2/pool.ex')
        self.assertEqual({sites[i]['mfa'] for i in (179, 180)}, {'prepare/2', 'execute/3'})
        for number in amendment['added_occurrences']:
            site = sites[number]
            line = (ROOT / site['source']).read_text().splitlines()[site['line'] - 1]
            self.assertIn('callback.(' if number == 178 else 'module.', line)
        self.assertEqual(len(bundle['occurrences']), 206)
        rc9 = [site for group in review.GROUPS for site in rewind(proof(group), '1.0.0-rc.11')]
        self.assertEqual(identity_digest(rc9),
                         (180, 180, amendment['reviewed_inventory_reconciliation']['sha256']))
        self.assertEqual(amendment['local_compiled_diagnostic']['status'],
                         'DIAGNOSTIC_ONLY_STRICT_RELEASE_PENDING')

    def test_m1_additions_retain_exact_reviewed_q2_origins(self):
        sites = {site['inventory_occurrence']: site for site in rewind(proof('quic'), '1.0.0-rc.11')}
        self.assertEqual(set(sites), set(range(1, 29)) | {176, 177})
        for number, mfa, line in ((176, 'handle_event/4', 770), (177, 'path_timer/1', 1422)):
            with self.subTest(occurrence=number):
                self.assertEqual({key: sites[number][key] for key in
                                  ('module', 'mfa', 'line', 'kind', 'source', 'proof')},
                                 dict(module='Quic.Connection', mfa=mfa, line=line,
                                      kind='unresolved_module_dispatch',
                                      source='apps/elixir_quic/lib/quic/connection.ex', proof='Q2'))

    def test_all_connection_bindings_match_current_calls_and_preserve_failed_history(self):
        quic = proof('quic')
        sites = {site['inventory_occurrence']: (site['mfa'], site['line'])
                 for site in rewind(quic, '1.0.0-rc.11') if site['module'] == 'Quic.Connection'}
        self.assertEqual(sites, {
            2: ('begin_closing/2', 1551), 3: ('begin_closing/2', 1507),
            4: ('closing_timer/1', 1437), 5: ('draining_timer/1', 1442),
            6: ('expired?/1', 1898), 7: ('eligible_send/1', 1382),
            8: ('handle_event/4', 338), 9: ('handle_event/4', 714),
            10: ('handle_event/4', 725), 11: ('handle_event/4', 737),
            12: ('handle_event/4', 747), 13: ('handshake_deadline/3', 128),
            14: ('idle_timer/1', 1429), 15: ('local_send/3', 1613),
            16: ('local_send/3', 1615), 17: ('local_send/3', 1618),
            18: ('receive_authenticated/6', 951), 19: ('recovery_timer/1', 1411),
            20: ('refresh_idle/1', 1461), 176: ('handle_event/4', 770),
            177: ('path_timer/1', 1422),
        })
        source = (ROOT / 'apps/elixir_quic/lib/quic/connection.ex').read_text().splitlines()
        current = {site['inventory_occurrence']: site['line'] for site in quic['occurrences']
                   if site['module'] == 'Quic.Connection'}
        self.assertEqual(set(current), set(sites) | set(range(182, 188)))
        for number, line in current.items():
            with self.subTest(occurrence=number):
                self.assertIn('adapter.', source[line - 1])
        amendment = next(item for item in quic['source_review_amendments']
                         if item.get('failed_strict_candidate', {}).get('artifact') == 13572580831)
        self.assertEqual(amendment['failed_strict_candidate']['artifact'], 13572580831)
        self.assertEqual(amendment['failed_strict_candidate']['directed_status'], 'FAIL')
        self.assertEqual(len(amendment['occurrence_rebindings']), 21)
        previous_sites = sites | {
            item['inventory_occurrence']: (item['mfa'], item['previous_line'])
            for item in pto_amendment(quic)['occurrence_rebindings']}
        for item in amendment['occurrence_rebindings']:
            self.assertEqual(item['line'], item['previous_line'] + 1)
            self.assertEqual(previous_sites[item['inventory_occurrence']], (item['mfa'], item['line']))

    def test_current_and_historical_complete_occurrence_multisets_remain_bound(self):
        bundle = review.load(ROOT, '1.0.0-rc.0', PACKAGES)
        proof = json.loads((ROOT / 'docs/no-otp-directed-quic-proof.json').read_text())
        amendment = pto_amendment(proof)
        tls = json.loads((ROOT / 'docs/no-otp-directed-tls-proof.json').read_text())
        tls_amendment = next(item for item in tls['source_review_amendments']
                             if item.get('change', '').startswith('RC8 issue #157'))
        evidence = tls_amendment['reviewed_inventory_reconciliation']
        original = [site for group in review.GROUPS for site in historical_sites(
            json.loads((ROOT / f'docs/no-otp-directed-{group}-proof.json').read_text()))]
        identities = sorted((site['module'].removeprefix(':'), site['line'], site['kind'])
                            for site in original)
        digest = hashlib.sha256(json.dumps(identities, separators=(',', ':')).encode()).hexdigest()
        self.assertEqual(len(identities), 177)
        self.assertEqual(len(set(identities)), 177)
        self.assertEqual(digest, evidence['sha256'])
        self.assertEqual(evidence['duplicates'], 0)
        self.assertEqual(evidence['status'], 'SOURCE_IDENTITIES_ONLY_COMPILED_CERTIFICATION_NOT_RUN')
        self.assertEqual(tls_amendment['occurrence_rebindings'], [dict(
            inventory_occurrence=74, mfa='verify_certificate/3', previous_line=390, line=396)])
        tls_sites = {site['inventory_occurrence']: site for site in historical_sites(tls)}
        for item in tls_amendment['occurrence_rebindings']:
            site = tls_sites[item['inventory_occurrence']]
            self.assertEqual((site['mfa'], site['line']), (item['mfa'], item['line']))
            self.assertIn('case verifier.(', (ROOT / site['source']).read_text().splitlines()[site['line'] - 1])
        old_lines = {item['inventory_occurrence']: item['previous_line']
                     for item in tls_amendment['occurrence_rebindings']}
        prior_identities = []
        for group in review.GROUPS:
            group_proof = json.loads((ROOT / f'docs/no-otp-directed-{group}-proof.json').read_text())
            for site in historical_sites(group_proof):
                prior_identities.append((site['module'].removeprefix(':'),
                                         old_lines.get(site['inventory_occurrence'], site['line']),
                                         site['kind']))
        prior_digest = hashlib.sha256(json.dumps(sorted(prior_identities), separators=(',', ':')).encode()).hexdigest()
        self.assertEqual(prior_digest, amendment['reviewed_inventory_reconciliation']['sha256'])
        old_lines.update({item['inventory_occurrence']: item['previous_line']
                          for item in amendment['occurrence_rebindings']})
        old_identities = []
        for group in review.GROUPS:
            group_proof = json.loads((ROOT / f'docs/no-otp-directed-{group}-proof.json').read_text())
            for site in historical_sites(group_proof):
                old_identities.append((site['module'].removeprefix(':'),
                                       old_lines.get(site['inventory_occurrence'], site['line']),
                                       site['kind']))
        old_digest = hashlib.sha256(json.dumps(sorted(old_identities), separators=(',', ':')).encode()).hexdigest()
        historical = next(item['exact_remote_raw_set_reconciliation']
                          for item in proof['source_review_amendments']
                          if 'exact_remote_raw_set_reconciliation' in item)
        self.assertEqual(old_digest, historical['sha256'])
        self.assertEqual(historical['missing'], 0)
        self.assertEqual(historical['extra'], 0)
        self.assertEqual(historical['duplicates'], 0)

    def test_pto_review_preserves_unresolved_root_context_findings(self):
        amendment = pto_amendment(proof('quic'))
        quic = amendment['compiled_quic_reconciliation']
        self.assertEqual((quic['checked_beams'], quic['raw_dispatches']), (45, 30))
        self.assertEqual((quic['missing'], quic['extra'], quic['changed_owning_mfas']), (0, 0, 0))
        self.assertTrue(quic['root_test_and_quality_connection_mfa_lines_equal'])
        root = amendment['whole_root_diagnostic_audit']
        self.assertEqual((root['raw_dispatches'], root['reviewed_sites_found']), (186, 177))
        self.assertEqual(root['remaining_site_count'], 9)
        self.assertEqual(sum(item['count'] for item in root['remaining_unreviewed_local_sites']), 9)
        self.assertEqual(root['missing_reviewed_sites'], 0)
        self.assertEqual(root['strict_full_release_status'], 'PENDING_REMOTE_RERUN')

    def test_missing_original_or_m1_ids_duplicate_and_unreviewed_ids_fail(self):
        parse = json.loads
        changes = [
            lambda sites: [site for site in sites if site['inventory_occurrence'] != 1],
            lambda sites: [site for site in sites if site['inventory_occurrence'] != 176],
            lambda sites: [site for site in sites if site['inventory_occurrence'] != 177],
            lambda sites: sites + [copy.deepcopy(sites[-1])],
            lambda sites: sites + [dict(sites[-1], inventory_occurrence=207)],
        ]
        for change in changes:
            def load_with_changed_quic_sites(text):
                document = parse(text)
                if document.get('review') == 'no-otp-directed-quic-proof.md':
                    document['occurrences'] = change(document['occurrences'])
                return document

            with self.subTest(change=changes.index(change)), \
                    patch.object(review.json, 'loads', side_effect=load_with_changed_quic_sites), \
                    self.assertRaisesRegex(ValueError, 'reviewed occurrence coverage'):
                review.load(ROOT, '1.0.0-rc.0', PACKAGES)

    def test_rc11_renewal_binds_current_sources_additions_and_rewound_history(self):
        bundle = review.load(ROOT, '1.0.0-rc.11', PACKAGES)
        production = {name: digest for name, digest in bundle['sources'].items()
                      if name.split('/')[0] in PACKAGES}
        census = hashlib.sha256(json.dumps(production, sort_keys=True).encode()).hexdigest()
        tokens = {'TLS-7': 'fun.(', 'Q2': 'adapter.', 'Q4': 'adapter.', 'H3-1': 'transport.',
                  'H3-2': 'ops.', 'WT-1': ('backend.', 'fun.(')}
        added, current = [], []
        for group in review.GROUPS:
            group_proof = proof(group)
            current += group_proof['occurrences']
            if group == 'telemetry':
                continue
            amendment = group_proof['source_review_amendments'][-1]
            self.assertEqual(amendment['release_version'], '1.0.0-rc.11')
            self.assertEqual(amendment['active_production_source_census']['files'], 267)
            self.assertEqual(amendment['active_production_source_census']['sorted_path_sha256_json'], census)
            for name, change in amendment['changed_source_inputs'].items():
                self.assertEqual(group_proof['source_inputs_sha256'][name], change['sha256'])
                self.assertNotEqual(change['previous_sha256'], change['sha256'])
            sites = {site['inventory_occurrence']: site for site in group_proof['occurrences']}
            for number in amendment['added_occurrences']:
                site = sites[number]
                line = (ROOT / site['source']).read_text().splitlines()[site['line'] - 1]
                with self.subTest(occurrence=number):
                    self.assertTrue(any(token in line for token in
                                        (tokens[site['proof']] if isinstance(tokens[site['proof']], tuple)
                                         else (tokens[site['proof']],))))
            added += amendment['added_occurrences']
            reconciliation = amendment['reviewed_inventory_reconciliation']
            self.assertEqual((reconciliation['count'], reconciliation['duplicates']), (206, 0))
            self.assertEqual(identity_digest(bundle['occurrences']),
                             (206, 206, reconciliation['sha256']))
        self.assertEqual(sorted(added), list(range(181, 207)))
        self.assertEqual(sorted(site['inventory_occurrence'] for site in current), list(range(1, 207)))

    def test_native_source_and_compiled_release_binding(self):
        result = subprocess.run(['elixir', str(Path(__file__).with_suffix('.exs'))],
                                env=dict(os.environ), stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertRegex(result.stdout, r'(?:10 tests, 0 failures|Result: 10 passed)')

    def fixture(self):
        site = dict(module='HTTP', mfa='run/1', line=2, kind='unresolved_fun_invocation',
                    source='http_fetch/lib/http.ex', proof='HTTP-1')
        inspection = dict(module='HTTP', beam='/release/lib/http_fetch-1/ebin/Elixir.HTTP.beam',
                          sha256='a' * 64)
        raw = dict(beam=inspection['beam'], line=2, kind=site['kind'], resolution='unconfirmed')
        bundle = dict(sources={site['source']: 'b' * 64}, occurrences=[site],
                      reviews={'review.md': 'c' * 64})
        receipt = dict(status='PASS', scope=review.SCOPE, sources=copy.deepcopy(bundle['sources']),
                       reviews=copy.deepcopy(bundle['reviews']), raw_dispatch_count=1,
                       remaining_dispatches=[],
                       beam_bindings=[dict(inspection, build_sha256=inspection['sha256'],
                                           source=site['source'], source_sha256='b' * 64)],
                       reviewed_dispatches=[dict(site, beam=inspection['beam'],
                                                 beam_sha256=inspection['sha256'])])
        artifacts = dict(checked_beams=1, beam_inspections=[inspection],
                         unresolved_dispatch=[raw], directed_review=receipt)
        return artifacts, bundle

    def test_independent_receipt_reconciliation_preserves_raw_findings(self):
        artifacts, bundle = self.fixture()
        original = copy.deepcopy(artifacts)
        review.validate(artifacts, bundle)
        self.assertEqual(artifacts, original)

    def test_new_missing_duplicate_or_misattributed_findings_fail(self):
        changes = [
            lambda a: a['unresolved_dispatch'].clear(),
            lambda a: a['unresolved_dispatch'].append(dict(a['unresolved_dispatch'][0], line=3)),
            lambda a: a['directed_review']['reviewed_dispatches'].append(copy.deepcopy(a['directed_review']['reviewed_dispatches'][0])),
            lambda a: a['directed_review']['reviewed_dispatches'][0].update(mfa='other/1'),
            lambda a: a['directed_review']['reviewed_dispatches'][0].update(proof='TLS-1'),
            lambda a: a['directed_review']['reviewed_dispatches'][0].update(beam_sha256='d' * 64),
            lambda a: a['directed_review']['remaining_dispatches'].append('unproved'),
        ]
        for change in changes:
            with self.subTest(change=changes.index(change)):
                artifacts, bundle = self.fixture()
                change(artifacts)
                with self.assertRaises(ValueError):
                    review.validate(artifacts, bundle)

    def test_unbound_sources_modules_build_bytes_and_forged_status_fail(self):
        changes = [
            lambda r: r.update(status='FAIL'),
            lambda r: r.update(scope='all_arbitrary_callers'),
            lambda r: r['sources'].update({'extra/lib/code.ex': 'd' * 64}),
            lambda r: r['reviews'].clear(),
            lambda r: r['beam_bindings'].clear(),
            lambda r: r['beam_bindings'].append(copy.deepcopy(r['beam_bindings'][0])),
            lambda r: r['beam_bindings'][0].update(build_sha256='d' * 64),
            lambda r: r['beam_bindings'][0].update(source='unreviewed.ex'),
            lambda r: r['beam_bindings'][0].update(source_sha256='d' * 64),
        ]
        for change in changes:
            with self.subTest(change=changes.index(change)):
                artifacts, bundle = self.fixture()
                change(artifacts['directed_review'])
                with self.assertRaises(ValueError):
                    review.validate(artifacts, bundle)

    def test_strict_gate_requires_a_bound_receipt_and_keeps_every_other_artifact_check(self):
        artifacts, bundle = self.fixture()
        artifacts.update(checked_app_files=10, checked_rel_files=1, checked_boot_files=1,
                         ssl_app_dependencies=[], ssl_bundle_paths=[], ssl_boot_entries=[],
                         direct_otp_ssl_imports=[], missing_abstract_code=[], duplicate_package_apps=[],
                         package_versions={package: '1.0.0-rc.0' for package in gate.PACKAGES})
        with self.assertRaisesRegex(gate.GateError, 'unresolved_dispatch'):
            gate.validate_artifacts(artifacts, '1.0.0-rc.0')
        gate.validate_artifacts(artifacts, '1.0.0-rc.0', directed_review=bundle)
        for field in ('ssl_app_dependencies', 'ssl_bundle_paths', 'ssl_boot_entries',
                      'direct_otp_ssl_imports', 'missing_abstract_code', 'duplicate_package_apps'):
            with self.subTest(field=field), self.assertRaisesRegex(gate.GateError, field):
                gate.validate_artifacts(dict(artifacts, **{field: ['forbidden']}), '1.0.0-rc.0',
                                        directed_review=bundle)

    def test_cli_explicitly_requests_strict_directed_proof_for_published_release(self):
        from test_no_otp_consumer_gate import plan
        argv = ['gate', '1.0.0-rc.0', '/archives', '/stage', '--source-root', '/source',
                '--source-sha', 'a' * 40, '--peer-plan', '/plan.json', '--output', '/fresh',
                '--published', '--directed-review']
        with patch.object(gate.sys, 'argv', argv), \
                patch.object(Path, 'read_text', return_value=json.dumps(plan())), \
                patch.object(gate, 'run', return_value={'gate': 'test', 'status': 'PASS', 'output': '/fresh'}) as run, \
                patch('builtins.print'):
            gate.main()
        self.assertEqual(run.call_args.kwargs, dict(published=True, directed_review=True))

    def test_diagnostic_mode_cannot_bypass_a_failed_directed_proof(self):
        from test_no_otp_consumer_gate import plan
        with self.assertRaisesRegex(gate.GateError, 'directed review requires the strict'):
            gate.run('1.0.0-rc.0', Path('/archives'), Path('/stage'), Path('/source'),
                     'a' * 40, plan(), Path('/fresh'), directed_review=True,
                     collect_blocked_traffic=True)


if __name__ == '__main__':
    unittest.main()
