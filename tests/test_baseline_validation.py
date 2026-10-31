import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel.cli import main
from sentinel.integrity import create, verify


class BaselineValidationTests(unittest.TestCase):
    def test_invalid_baselines_fail_without_reading_targets(self):
        cases = ["{}", "[]", '{"x":"bad"}',
                 json.dumps({"": "0" * 64}),
                 json.dumps({"x": "A" * 64}),
                 '{"x":"' + "0" * 64 + '","x":"' + "1" * 64 + '"}']
        with tempfile.TemporaryDirectory() as tmp:
            baseline = Path(tmp) / "baseline.json"
            for content in cases:
                with self.subTest(content=content):
                    baseline.write_text(content, encoding="utf-8")
                    with patch("sentinel.integrity.digest") as digest:
                        with self.assertRaises(ValueError):
                            verify(str(baseline))
                        digest.assert_not_called()

    def test_deleted_target_fails_and_remaining_files_are_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing, present = root / "missing", root / "present"
            baseline = root / "baseline.json"
            missing.write_text("original", encoding="utf-8")
            present.write_text("original", encoding="utf-8")
            create([str(missing), str(present)], str(baseline))
            missing.unlink()
            self.assertEqual(verify(str(baseline)),
                             [(str(missing), False), (str(present), True)])
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["baseline", "verify", str(baseline)]), 2)
            self.assertIn("FAIL ", output.getvalue())
            self.assertIn("OK   ", output.getvalue())

    def test_invalid_baseline_cli_has_diagnostic_and_failure_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            baseline = Path(tmp) / "baseline.json"
            for content in ("{}", "not json"):
                baseline.write_text(content, encoding="utf-8")
                error = io.StringIO()
                with contextlib.redirect_stderr(error):
                    self.assertEqual(main(["baseline", "verify", str(baseline)]), 2)
                self.assertIn("Baseline verification failed:", error.getvalue())

    def test_empty_creation_does_not_write_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "baseline.json"
            with self.assertRaises(ValueError):
                create([], str(output))
            self.assertFalse(output.exists())
