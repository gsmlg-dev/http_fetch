"""Prove the negative certificate differs by expiry, rather than trust or name."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cryptography import x509

sys.path.insert(0, str(Path(__file__).resolve().parent))
from public_gate import certificates


class CertificateTest(unittest.TestCase):
    def test_common_trust_and_isolated_expiry(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            certificates(fixture)
            valid = x509.load_pem_x509_certificate((fixture / "server.pem").read_bytes())
            expired = x509.load_pem_x509_certificate((fixture / "expired.pem").read_bytes())
            now = datetime.now(timezone.utc)
            self.assertGreater(valid.not_valid_after_utc, now + timedelta(days=6))
            self.assertLess(expired.not_valid_after_utc, now)
            self.assertEqual(valid.issuer, expired.issuer)
            self.assertEqual(valid.extensions.get_extension_for_class(x509.SubjectAlternativeName).value,
                             expired.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)
            positive = subprocess.run(["openssl", "verify", "-CAfile", str(fixture / "ca.pem"), str(fixture / "server.pem")], capture_output=True, text=True)
            self.assertEqual(positive.returncode, 0, positive.stdout + positive.stderr)
            negative = subprocess.run(["openssl", "verify", "-CAfile", str(fixture / "ca.pem"), str(fixture / "expired.pem")], capture_output=True, text=True)
            self.assertNotEqual(negative.returncode, 0)
            self.assertIn("certificate has expired", negative.stderr)
            wrong = subprocess.run(["openssl", "verify", "-CAfile", str(fixture / "wrong-ca.pem"), str(fixture / "server.pem")], capture_output=True, text=True)
            self.assertNotEqual(wrong.returncode, 0)
            self.assertIn("unable to get local issuer certificate", wrong.stderr)


if __name__ == "__main__":
    unittest.main()
