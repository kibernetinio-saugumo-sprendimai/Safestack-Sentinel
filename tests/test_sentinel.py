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
        completed = Mock(returncode=0, stdout="ok", stderr="")
        with patch("sentinel.checks.subprocess.run", return_value=completed) as proc:
            self.assertEqual(run(["/usr/bin/true"]), "ok")
        self.assertEqual(proc.call_args.kwargs["env"], {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})

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

class RegressionTests(unittest.TestCase):
    def test_failed_command_is_unavailable(self):
        with patch('sentinel.checks.subprocess.run', return_value=Mock(returncode=1, stdout='', stderr='denied')):
            self.assertTrue(run(['/usr/bin/false']).startswith('unavailable:'))

    def test_socket_failures_are_unknown(self):
        from sentinel.checks import listening_ports
        with patch('sentinel.checks.platform.system', return_value='Linux'):
            with patch('sentinel.checks.trusted_command', return_value=None):
                self.assertEqual(listening_ports().status, 'unknown')
            with patch('sentinel.checks.trusted_command', return_value='/usr/bin/ss'), patch('sentinel.checks.run', return_value='unavailable: denied'):
                self.assertEqual(listening_ports().status, 'unknown')
            with patch('sentinel.checks.trusted_command', return_value='/usr/bin/ss'), patch('sentinel.checks.run', return_value='Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port'):
                self.assertEqual(listening_ports().status, 'pass')

    def test_ssh_uses_effective_configuration(self):
        from sentinel.checks import ssh_check
        with patch('sentinel.checks.trusted_command', return_value='/usr/sbin/sshd'), patch('sentinel.checks.run', return_value='permitrootlogin yes\npasswordauthentication yes') as command:
            self.assertEqual(ssh_check().status, 'fail')
            command.assert_called_once_with(['/usr/sbin/sshd', '-T'])
        with patch('sentinel.checks.trusted_command', return_value=None):
            self.assertEqual(ssh_check().status, 'unknown')
        with patch('sentinel.checks.trusted_command', return_value='/usr/sbin/sshd'), patch('sentinel.checks.run', return_value='permitrootlogin no\npasswordauthentication no'):
            self.assertEqual(ssh_check().status, 'review')

    def test_plan_applies_profile(self):
        from sentinel.cli import main
        from sentinel.profiles import load
        profile = load('macos-desktop')
        self.assertNotIn('ssh', profile['checks'])
        with tempfile.TemporaryDirectory() as tmp, patch('sentinel.cli.run_all', return_value=[]) as checks:
            main(['plan', '--profile', 'macos-desktop', '--json', str(Path(tmp)/'plan.json')])
            checks.assert_called_once_with(profile['checks'])
        with self.assertRaises(ValueError):
            load('../default')

    def test_pdf_offsets_point_to_objects(self):
        from sentinel.pdf import write_pdf
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)/'report.pdf'
            write_pdf(build([]), str(output))
            data = output.read_bytes()
            xref = int(data.split(b'startxref\n')[1].splitlines()[0])
            self.assertTrue(data[xref:].startswith(b'xref\n'))
            rows = data[xref:].splitlines()[3:8]
            for number, row in enumerate(rows, 1):
                offset = int(row.split()[0])
                self.assertTrue(data[offset:].startswith(f'{number} 0 obj\n'.encode()))

    def test_profile_runs_only_selected_checks(self):
        from sentinel.checks import run_all
        selected = Mock(return_value=Finding("platform", "info", "pass", "ok"))
        excluded = Mock(side_effect=AssertionError("excluded check executed"))
        with patch.dict('sentinel.checks.CHECKS', {"platform": selected, "ssh": excluded}, clear=True):
            self.assertEqual(len(run_all(["platform"])), 1)
            selected.assert_called_once_with()
            excluded.assert_not_called()
