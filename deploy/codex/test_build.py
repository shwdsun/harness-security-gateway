"""Offline falsifiers for the artifact boundary; no native or service execution."""

import hashlib
import importlib.util
import os
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("offline_bundle", Path(__file__).with_name("build.py"))
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


class InputsTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.inputs = self.root / "inputs"
        self.inputs.mkdir(mode=0o700)
        self.source = self.inputs / "runner"
        self.source.write_bytes(b"fixed-fixture")
        self.source.chmod(0o555)
        self.expected = {"bytes": 13, "sha256": hashlib.sha256(b"fixed-fixture").hexdigest(),
                         "executable": True}

    def test_extra_entry_rejected_without_reading_it(self):
        # A FIFO would hang an indiscriminate archive/hash of the input tree.
        os.mkfifo(self.inputs / "auth.json", 0o600)
        with self.assertRaisesRegex(ValueError, "unexpected entries"):
            bundle.check_layout(self.inputs, {"runner": self.expected})

    def test_symlink_hardlink_and_writable_input_rejected(self):
        for kind in ("symlink", "hardlink", "writable"):
            with self.subTest(kind=kind):
                other = self.root / kind
                other.mkdir(mode=0o700)
                candidate = other / "runner"
                if kind == "symlink":
                    candidate.symlink_to(self.source)
                elif kind == "hardlink":
                    os.link(self.source, candidate)
                else:
                    candidate.write_bytes(b"fixed-fixture")
                    candidate.chmod(0o777)
                with self.assertRaises(ValueError):
                    bundle.check_layout(other, {"runner": self.expected})
                candidate.unlink()

    def test_wrong_bytes_and_overwrite_rejected(self):
        bundle.check_layout(self.inputs, {"runner": self.expected})
        destination = self.root / "copy"
        bundle.copy_verified(self.source, destination, self.expected)
        self.assertEqual(destination.read_bytes(), b"fixed-fixture")
        with self.assertRaises(FileExistsError):
            bundle.copy_verified(self.source, destination, self.expected)
        self.source.chmod(0o700)
        self.source.write_bytes(b"wrong-fixture")
        self.source.chmod(0o555)
        with self.assertRaisesRegex(ValueError, "content mismatch"):
            bundle.copy_verified(self.source, self.root / "bad-copy", self.expected)

    def test_intermediate_package_directories_are_private_under_group_umask(self):
        destination = self.root / "package" / "resources" / "bin" / "runner"
        previous = os.umask(0o002)
        try:
            bundle.copy_verified(self.source, destination, self.expected)
        finally:
            os.umask(previous)
        for path in [self.root / "package", self.root / "package/resources", destination.parent]:
            self.assertEqual(path.stat().st_mode & 0o7777, 0o700)

    def test_archive_ignores_input_mtime_and_directory_location(self):
        one = self.root / "one.tar"
        two = self.root / "two.tar"
        bundle.archive(self.inputs, one)
        os.utime(self.source, (42, 42))
        second = self.root / "second"
        self.inputs.rename(second)
        bundle.archive(second, two)
        self.assertEqual(one.read_bytes(), two.read_bytes())
        with tarfile.open(one) as archive:
            entry = archive.getmembers()[0]
            self.assertEqual((entry.name, entry.uid, entry.gid, entry.mtime), ("runner", 0, 0, 0))
            self.assertTrue(entry.isfile())
        with self.assertRaises(FileExistsError):
            bundle.archive(second, one)


if __name__ == "__main__":
    unittest.main()
