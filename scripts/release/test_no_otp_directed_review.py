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


class DirectedReviewTests(unittest.TestCase):
    def test_review_bundle_covers_all_original_sites_and_all_production_sources(self):
        bundle = review.load(ROOT, '1.0.0-rc.0', PACKAGES)
        self.assertEqual(len(bundle['occurrences']), 177)
        self.assertEqual(len([name for name in bundle['sources'] if name.split('/')[0] in PACKAGES]), 246)
        self.assertEqual(len(bundle['reviews']), 10)
        self.assertEqual(bundle['versions']['http_fetch'], '1.0.0-rc.0')

    def test_m1_additions_retain_exact_reviewed_q2_origins(self):
        proof = json.loads((ROOT / 'docs/no-otp-directed-quic-proof.json').read_text())
        sites = {site['inventory_occurrence']: site for site in proof['occurrences']}
        self.assertEqual(set(sites), set(range(1, 29)) | {176, 177})
        for number, mfa, line in ((176, 'handle_event/4', 768), (177, 'path_timer/1', 1420)):
            with self.subTest(occurrence=number):
                self.assertEqual({key: sites[number][key] for key in
                                  ('module', 'mfa', 'line', 'kind', 'source', 'proof')},
                                 dict(module='Quic.Connection', mfa=mfa, line=line,
                                      kind='unresolved_module_dispatch',
                                      source='apps/elixir_quic/lib/quic/connection.ex', proof='Q2'))

    def test_all_connection_bindings_match_current_calls_and_preserve_failed_history(self):
        proof = json.loads((ROOT / 'docs/no-otp-directed-quic-proof.json').read_text())
        sites = {site['inventory_occurrence']: (site['mfa'], site['line'])
                 for site in proof['occurrences'] if site['module'] == 'Quic.Connection'}
        self.assertEqual(sites, {
            2: ('begin_closing/2', 1549), 3: ('begin_closing/2', 1505),
            4: ('closing_timer/1', 1435), 5: ('draining_timer/1', 1440),
            6: ('expired?/1', 1887), 7: ('eligible_send/1', 1380),
            8: ('handle_event/4', 338), 9: ('handle_event/4', 714),
            10: ('handle_event/4', 725), 11: ('handle_event/4', 737),
            12: ('handle_event/4', 747), 13: ('handshake_deadline/3', 128),
            14: ('idle_timer/1', 1427), 15: ('local_send/3', 1602),
            16: ('local_send/3', 1604), 17: ('local_send/3', 1607),
            18: ('receive_authenticated/6', 949), 19: ('recovery_timer/1', 1409),
            20: ('refresh_idle/1', 1459), 176: ('handle_event/4', 768),
            177: ('path_timer/1', 1420),
        })
        source = (ROOT / 'apps/elixir_quic/lib/quic/connection.ex').read_text().splitlines()
        for number, (_, line) in sites.items():
            with self.subTest(occurrence=number):
                self.assertIn('adapter.', source[line - 1])
        amendment = proof['source_review_amendments'][-1]
        self.assertEqual(amendment['failed_strict_candidate']['artifact'], 13572580831)
        self.assertEqual(amendment['failed_strict_candidate']['directed_status'], 'FAIL')
        self.assertEqual(len(amendment['occurrence_rebindings']), 21)
        for item in amendment['occurrence_rebindings']:
            self.assertEqual(item['line'], item['previous_line'] + 1)
            self.assertEqual(sites[item['inventory_occurrence']], (item['mfa'], item['line']))

    def test_complete_normalized_occurrence_set_matches_remote_failure_evidence(self):
        bundle = review.load(ROOT, '1.0.0-rc.0', PACKAGES)
        proof = json.loads((ROOT / 'docs/no-otp-directed-quic-proof.json').read_text())
        evidence = proof['source_review_amendments'][-1]['exact_remote_raw_set_reconciliation']
        identities = sorted((site['module'].removeprefix(':'), site['line'], site['kind'])
                            for site in bundle['occurrences'])
        digest = hashlib.sha256(json.dumps(identities, separators=(',', ':')).encode()).hexdigest()
        self.assertEqual(len(identities), 177)
        self.assertEqual(len(set(identities)), 177)
        self.assertEqual(digest, evidence['sha256'])
        self.assertEqual(evidence['missing'], 0)
        self.assertEqual(evidence['extra'], 0)
        self.assertEqual(evidence['duplicates'], 0)

    def test_missing_original_or_m1_ids_duplicate_and_unreviewed_ids_fail(self):
        parse = json.loads
        changes = [
            lambda sites: [site for site in sites if site['inventory_occurrence'] != 1],
            lambda sites: [site for site in sites if site['inventory_occurrence'] != 176],
            lambda sites: [site for site in sites if site['inventory_occurrence'] != 177],
            lambda sites: sites + [copy.deepcopy(sites[-1])],
            lambda sites: sites + [dict(sites[-1], inventory_occurrence=178)],
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

    def test_native_source_and_compiled_release_binding(self):
        result = subprocess.run(['elixir', str(Path(__file__).with_suffix('.exs'))],
                                env=dict(os.environ), stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertRegex(result.stdout, r'(?:9 tests, 0 failures|Result: 9 passed)')

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
