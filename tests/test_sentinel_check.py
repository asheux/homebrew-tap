import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location("check_sentinel", Path(__file__).resolve().parents[1] / "scripts/check-sentinel.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / "unpacked"
        self.output.mkdir()
        self.files = {"sentinel.exe": b"server", "Sentinel-Atlas-0.1.0-windows-x64.exe": b"installer"}
        self.files.update({f"test-{suite}.exe": suite.encode() for suite in checker.SUITES})
        self.manifest = dict(schema=1, os="windows", arch="x64", version="0.1.0",
            source_revision="a" * 40, source_dirty=False, files=[
                dict(file=name, bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
                for name, data in self.files.items()])

    def bundle(self):
        path = self.root / "bundle.zip"
        with zipfile.ZipFile(path, "w") as archive:
            for name, data in self.files.items():
                archive.writestr(name, data)
            archive.writestr("checks.json", json.dumps(self.manifest))
        return path, checker.digest(path)

    def test_valid_compiled_bundle(self):
        path, digest = self.bundle()
        self.assertEqual(checker.unpack(path, digest, self.output), self.manifest)
        self.assertEqual({p.name for p in self.output.iterdir()}, set(self.files))

    def test_changed_download(self):
        path, _ = self.bundle()
        with self.assertRaisesRegex(ValueError, "checksum"):
            checker.unpack(path, "0" * 64, self.output)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_missing_suite(self):
        del self.files["test-platform.exe"]
        with self.assertRaisesRegex(ValueError, "contents"):
            checker.unpack(*self.bundle(), self.output)

    def test_escape_path(self):
        self.files["../outside.exe"] = self.files.pop("sentinel.exe")
        with self.assertRaisesRegex(ValueError, "Invalid file"):
            checker.unpack(*self.bundle(), self.output)
        self.assertFalse((self.root / "outside.exe").exists())

    def test_private_source_is_not_an_accepted_payload(self):
        self.files["source.rs"] = self.files.pop("sentinel.exe")
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            checker.unpack(*self.bundle(), self.output)

    def test_changed_file(self):
        self.files["sentinel.exe"] = b"SERVER"
        with self.assertRaisesRegex(ValueError, "checksum"):
            checker.unpack(*self.bundle(), self.output)


if __name__ == "__main__":
    unittest.main()
