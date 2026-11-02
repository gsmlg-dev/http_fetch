"""Specific reviewed source and release binding, with adversarial receipt controls."""
import copy
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
        self.assertEqual(len(bundle['occurrences']), 175)
        self.assertEqual(len([name for name in bundle['sources'] if name.split('/')[0] in PACKAGES]), 244)
        self.assertEqual(len(bundle['reviews']), 10)
        self.assertEqual(bundle['versions']['http_fetch'], '1.0.0-rc.0')

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
