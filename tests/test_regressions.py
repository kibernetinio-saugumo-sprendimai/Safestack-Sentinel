import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from sentinel.checks import CommandResult, firewall_check, listening_ports, query, ssh_check, update_check
from sentinel.cli import main
from sentinel.plugins import discover
from sentinel.profiles import load, PROFILES
from sentinel.notify import telegram
from sentinel.report import build
from sentinel.model import Finding


class ObservationRegressions(unittest.TestCase):
    def listeners(self, result, system="Linux", command="/usr/bin/ss"):
        with patch("sentinel.checks.platform.system", return_value=system), \
             patch("sentinel.checks.trusted_command", return_value=command), \
             patch("sentinel.checks.query", return_value=result):
            return listening_ports()

    def test_missing_failed_and_unparseable_listener_queries_are_unknown(self):
        cases = [CommandResult(stderr="timeout"), CommandResult("garbage", "", 0),
                 CommandResult("", "permission denied", 1), CommandResult("", "", 0)]
        for result in cases:
            with self.subTest(result=result):
                self.assertEqual(self.listeners(result).status, "unknown")
        self.assertEqual(self.listeners(CommandResult(), command=None).status, "unknown")
        self.assertEqual(self.listeners(CommandResult(), system="Windows").status, "unknown")

    def test_header_only_ss_and_actual_listener(self):
        header = "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
        self.assertEqual(self.listeners(CommandResult(header, "", 0)).status, "pass")
        finding = self.listeners(CommandResult(header + "tcp LISTEN 0 10 0.0.0.0:22 0.0.0.0:*\n", "", 0))
        self.assertEqual(finding.status, "review")
        self.assertIn("1 TCP/UDP", finding.summary)

    def test_mac_listener_no_match_exit_is_not_assumed_safe(self):
        self.assertEqual(self.listeners(CommandResult("", "", 1), system="Darwin").status, "unknown")

    def test_failed_command_does_not_hide_return_code(self):
        with patch("sentinel.checks.subprocess.run", return_value=Mock(stdout="0 upgraded", stderr="error", returncode=1)):
            self.assertFalse(query(["/usr/bin/apt-get", "-s", "upgrade"]).ok)
        with patch("sentinel.checks.subprocess.run", side_effect=subprocess.TimeoutExpired("ss", 5)):
            self.assertFalse(query(["/usr/bin/ss"]).ok)

    def test_firewall_errors_are_unknown_even_when_output_contains_active(self):
        with patch("sentinel.checks.platform.system", return_value="Linux"), \
             patch("sentinel.checks.trusted_command", return_value="/usr/sbin/ufw"), \
             patch("sentinel.checks.query", return_value=CommandResult("Status: active", "error", 1)):
            self.assertEqual(firewall_check().status, "unknown")

    def test_apt_failed_result_with_zero_upgrades_is_unknown(self):
        with patch("sentinel.checks.platform.system", return_value="Linux"), \
             patch("sentinel.checks.trusted_command", return_value="/usr/bin/apt-get"), \
             patch("sentinel.checks.query", return_value=CommandResult("0 upgraded", "error", 1)):
            self.assertEqual(update_check().status, "unknown")

    def test_effective_ssh_defaults_not_regex_match_blocks(self):
        with patch("sentinel.checks.trusted_command", return_value="/usr/sbin/sshd"), \
             patch("sentinel.checks.query", return_value=CommandResult("permitrootlogin yes\npasswordauthentication yes\n", "", 0)) as call:
            self.assertEqual(ssh_check().status, "fail")
            call.assert_called_once_with(["/usr/sbin/sshd", "-T"])

    def test_secure_ssh_defaults_still_require_match_review(self):
        with patch("sentinel.checks.trusted_command", return_value="/usr/sbin/sshd"), \
             patch("sentinel.checks.query", return_value=CommandResult("permitrootlogin no\npasswordauthentication no\n", "", 0)):
            self.assertEqual(ssh_check().status, "review")

    def test_unavailable_ssh_is_unknown(self):
        with patch("sentinel.checks.trusted_command", return_value=None):
            self.assertEqual(ssh_check().status, "unknown")

    def test_failed_plugins_are_visible(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "broken.py").write_text('def run():\n    raise RuntimeError("hidden failure")\n')
            findings = discover(tmp)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].status, "unknown")
            self.assertEqual(findings[0].evidence, "RuntimeError")

    def test_profiles_and_plan_work_without_external_data_files(self):
        for name in PROFILES:
            self.assertEqual(load(name)["name"], name)
        with self.assertRaises(ValueError):
            load("../../etc/passwd")
        with tempfile.TemporaryDirectory() as tmp, patch("sentinel.cli.run_all", return_value=[]), contextlib.redirect_stdout(io.StringIO()):
            output = Path(tmp) / "plan.json"
            self.assertEqual(main(["plan", "--profile", "raspberry-pi-vpn", "--json", str(output)]), 0)
            self.assertEqual(json.loads(output.read_text())["profile"]["name"], "raspberry-pi-vpn")

    def test_telegram_invalid_token_cannot_change_request_path(self):
        with patch.dict("os.environ", {"SENTINEL_TELEGRAM_BOT_TOKEN": "1:a?redirect=bad", "SENTINEL_TELEGRAM_CHAT_ID": "123"}), \
             patch("sentinel.notify.HTTPSConnection") as connection:
            with self.assertRaises(ValueError):
                telegram({"score": 100, "generated_at": "now"})
            connection.assert_not_called()

    def test_telegram_uses_fixed_tls_host_without_following_redirects(self):
        with patch.dict("os.environ", {"SENTINEL_TELEGRAM_BOT_TOKEN": "1:abc", "SENTINEL_TELEGRAM_CHAT_ID": "123"}), \
             patch("sentinel.notify.HTTPSConnection") as connection:
            connection.return_value.getresponse.return_value.status = 302
            self.assertFalse(telegram({"score": 100, "generated_at": "now"}))
            connection.assert_called_once_with("api.telegram.org", timeout=8.0)
            connection.return_value.close.assert_called_once()

    def test_unknown_findings_and_empty_audits_cannot_claim_overall_pass(self):
        for findings in ([], [Finding("missing", "high", "unknown", "Cannot inspect")]):
            report = build(findings)
            self.assertEqual(report["assessment"], "review")
        self.assertEqual(build([Finding("bad", "high", "fail", "Failed")])["assessment"], "fail")
