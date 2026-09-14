import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel.integrity import create, verify as verify_baseline
from sentinel.model import Finding, score
from sentinel.report import build, write_html
from sentinel.signing import generate, sign, verify as verify_signature


class SentinelTests(unittest.TestCase):
    def test_score_and_report(self):
        report = build([Finding("x", "high", "fail", "bad")])
        self.assertEqual(report["score"], 80)
        self.assertEqual(report["findings"][0]["check"], "x")

    def test_integrity_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "target.txt"
            baseline = Path(tmp) / "baseline.json"
            target.write_text("safe", encoding="utf-8")
            create([str(target)], str(baseline))
            self.assertEqual(verify_baseline(str(baseline)), [(str(target), True)])
            target.write_text("changed", encoding="utf-8")
            self.assertEqual(verify_baseline(str(baseline)), [(str(target), False)])

    def test_html_escapes_finding_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = build([Finding("<x>", "low", "pass", "<script>alert(1)</script>")])
            output = Path(tmp) / "report.html"
            write_html(report, str(output))
            content = output.read_text(encoding="utf-8")
            self.assertNotIn("<script>alert(1)</script>", content)
            self.assertIn("&lt;script&gt;", content)

    def test_report_signature_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / "report.json"
            private = root / "private.pem"
            public = root / "public.pem"
            signature = root / "report.sig"
            report.write_text('{"safe":true}\n', encoding="utf-8")
            generate(str(private), str(public))
            sign(str(report), str(signature), str(private))
            self.assertTrue(verify_signature(str(report), str(signature), str(public)))
            report.write_text('{"safe":false}\n', encoding="utf-8")
            self.assertFalse(verify_signature(str(report), str(signature), str(public)))
