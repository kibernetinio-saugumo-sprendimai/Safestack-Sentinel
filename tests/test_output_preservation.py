import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel.cli import main
from sentinel.integrity import create
from sentinel.safeio import atomic_write
from sentinel.signing import generate


class OutputPreservationTests(unittest.TestCase):
    def test_keygen_preserves_existing_pair(self):
        with tempfile.TemporaryDirectory() as tmp:
            private, public = Path(tmp) / "private.pem", Path(tmp) / "public.pem"
            generate(str(private), str(public))
            original = (private.read_bytes(), public.read_bytes())
            with self.assertRaises(FileExistsError):
                generate(str(private), str(public))
            self.assertEqual(original, (private.read_bytes(), public.read_bytes()))

    def test_existing_public_key_prevents_private_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            private, public = Path(tmp) / "private.pem", Path(tmp) / "public.pem"
            public.write_bytes(b"existing public key")
            with self.assertRaises(FileExistsError):
                generate(str(private), str(public))
            self.assertFalse(private.exists())
            self.assertEqual(public.read_bytes(), b"existing public key")

    def test_keygen_rejects_identical_and_normalized_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sub").mkdir()
            key = root / "key.pem"
            for public in (key, root / "sub" / ".." / "key.pem"):
                with self.assertRaises(ValueError):
                    generate(str(key), str(public))
                self.assertFalse(key.exists())

    def test_keygen_preserves_dangling_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private, public = root / "private.pem", root / "public.pem"
            public.symlink_to(root / "missing.pem")
            with self.assertRaises(FileExistsError):
                generate(str(private), str(public))
            self.assertTrue(public.is_symlink())
            self.assertFalse(private.exists())

    def test_exclusive_publication_refuses_racing_destination(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "key.pem"
            real_link = os.link

            def competing_writer(source, destination):
                Path(destination).write_bytes(b"other writer")
                return real_link(source, destination)

            with patch("sentinel.safeio.os.link", side_effect=competing_writer):
                with self.assertRaises(FileExistsError):
                    atomic_write(str(output), b"new key", overwrite=False)
            self.assertEqual(output.read_bytes(), b"other writer")
            self.assertEqual(list(Path(tmp).iterdir()), [output])

    def test_baseline_rejects_source_output_and_aliases(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.txt"
            source.write_bytes(b"original")
            alias = root / "hardlink.txt"
            os.link(source, alias)
            symlink = root / "link.txt"
            symlink.symlink_to(source)
            for output in (source, alias, symlink):
                with self.assertRaises(ValueError):
                    create([str(source)], str(output))
                self.assertEqual(source.read_bytes(), b"original")

    def test_cli_rejections_are_reported_without_modifying_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.txt"
            source.write_bytes(b"original")
            commands = [(["keygen", str(source), str(source)], "Key generation failed"),
                        (["baseline", "create", str(source), str(source)], "Baseline creation failed")]
            for command, diagnostic in commands:
                error = io.StringIO()
                with contextlib.redirect_stderr(error):
                    self.assertEqual(main(command), 2)
                self.assertIn(diagnostic, error.getvalue())
                self.assertEqual(source.read_bytes(), b"original")
