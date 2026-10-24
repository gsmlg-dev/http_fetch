import unittest

from http2_compat import terminal_pass


class TrafficEvidenceTest(unittest.TestCase):
    def test_package_requires_exact_completed_traffic(self):
        complete = dict(result='PASS', gate='isolated_package_http2_traffic',
                        completed=True, packages=9, consumers=8, connections=8,
                        mixed_shared_connection=True, verified_tls=True, modes=[
                            dict(mode='h2c', protocol='h2c', verified_tls=False,
                                 consumers=4, connections=4, completed=True,
                                 mixed_shared_connection=True),
                            dict(mode='ex_ssl', protocol='h2', verified_tls=True,
                                 consumers=4, connections=4, completed=True,
                                 mixed_shared_connection=True)])
        self.assertTrue(terminal_pass([complete], 'package'))
        self.assertFalse(terminal_pass([dict(result='PASS', gate='original_package_metadata')], 'package'))
        for key in complete:
            partial = {name: value for name, value in complete.items() if name != key}
            self.assertFalse(terminal_pass([partial], 'package'), key)
        h2c, tls = complete['modes']
        for modes in ([h2c], [tls], [h2c, h2c], [tls, tls], ['h2c', 'ex_ssl'],
                      [h2c, {**tls, 'mode': {}}],
                      [h2c, {**tls, 'verified_tls': False}],
                      [h2c, {**tls, 'protocol': 'h2c'}],
                      [h2c, {**tls, 'consumers': 0}]):
            self.assertFalse(terminal_pass([{**complete, 'modes': modes}], 'package'), modes)
        self.assertFalse(terminal_pass([{**complete, 'consumers': 4, 'connections': 4}], 'package'))

    def test_source_requires_public_wire_observations(self):
        complete = dict(result='PASS', mode='wire-audit', public_client=True,
                        observations=2, completed=True)
        for kind in ('sse', 'ws'):
            self.assertTrue(terminal_pass([complete], kind))
            self.assertFalse(terminal_pass([dict(result='PASS')], kind))
            self.assertFalse(terminal_pass([{**complete, 'public_client': False}], kind))
            self.assertFalse(terminal_pass([{**complete, 'observations': 0}], kind))
        without_completed = {name: value for name, value in complete.items() if name != 'completed'}
        self.assertTrue(terminal_pass([without_completed], 'sse'))
        self.assertFalse(terminal_pass([without_completed], 'ws'))


if __name__ == '__main__':
    unittest.main()
