import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from sentinel.checks import run
from sentinel.dashboard import _is_safe_dashboard_path
from sentinel.history import append as append_history, load as load_history
from sentinel.integrity import create, verify as verify_baseline
from sentinel.model import Finding, score
from sentinel.report import build, write_html
from sentinel.safeio import atomic_write
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

    def test_integrity_rejects_symlink_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target.txt"
            link = root / "target-link.txt"
            baseline = root / "baseline.json"
            target.write_text("safe", encoding="utf-8")
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks are not supported")
            baseline.write_text(json.dumps({str(link): "0" * 64}), encoding="utf-8")
            with self.assertRaises(ValueError):
                verify_baseline(str(baseline))

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

    def test_signature_rejects_invalid_base64(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / "report.json"
            private = root / "private.pem"
            public = root / "public.pem"
            signature = root / "report.sig"
            report.write_text('{"safe":true}\n', encoding="utf-8")
            generate(str(private), str(public))
            signature.write_text("not a signature!\n", encoding="utf-8")
            self.assertFalse(verify_signature(str(report), str(signature), str(public)))

    def test_run_uses_sanitized_path(self):
        completed = Mock(stdout="ok", stderr="", returncode=0)
        with patch("sentinel.checks.subprocess.run", return_value=completed) as proc:
            self.assertEqual(run(["/usr/bin/true"]), "ok")
        self.assertEqual(proc.call_args.kwargs["env"], {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})

    def test_atomic_write_rejects_symlink_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / "real"
            link = root / "link"
            real.mkdir()
            try:
                link.symlink_to(real, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks are not supported")
            with self.assertRaises(ValueError):
                atomic_write(str(link / "report.json"), b"{}\n")

    def test_history_load_tails_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            history = Path(tmp) / "history.jsonl"
            for i in range(5):
                append_history({"i": i}, str(history))
            self.assertEqual(load_history(str(history), limit=2), [{"i": 3}, {"i": 4}])
            self.assertEqual(load_history(str(history), limit=0), [])

    def test_dashboard_rejects_symlink_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "reports"
            outside = Path(tmp) / "outside"
            root.mkdir()
            outside.mkdir()
            link = root / "outside"
            try:
                link.symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks are not supported")
            self.assertFalse(_is_safe_dashboard_path(root.resolve(), link / "secret.txt"))
            self.assertTrue(_is_safe_dashboard_path(root.resolve(), root / "report.html"))
