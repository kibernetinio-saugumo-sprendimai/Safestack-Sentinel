import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel.integrity import create, verify
from sentinel.model import Finding, score
from sentinel.report import build, write_html


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
            self.assertEqual(verify(str(baseline)), [(str(target), True)])
            target.write_text("changed", encoding="utf-8")
            self.assertEqual(verify(str(baseline)), [(str(target), False)])

    def test_html_escapes_finding_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = build([Finding("<x>", "low", "pass", "<script>alert(1)</script>")])
            output = Path(tmp) / "report.html"
            write_html(report, str(output))
            content = output.read_text(encoding="utf-8")
            self.assertNotIn("<script>alert(1)</script>", content)
            self.assertIn("&lt;script&gt;", content)
