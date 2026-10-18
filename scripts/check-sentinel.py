#!/usr/bin/env python3
"""Check a hash-pinned bundle of compiled Windows tests and its installer.

This script never needs Sentinel source or access to its private repository.
Installation runs only on a disposable GitHub-hosted Windows runner.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile

SUITES = {"backend", "monitor", "gateway", "platform", "desktop", "desktop-integration"}


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def unpack(bundle, expected, destination):
    if not re.fullmatch(r"[a-f0-9]{64}", expected) or digest(bundle) != expected:
        raise ValueError("Check bundle checksum mismatch")
    with zipfile.ZipFile(bundle) as archive:
        files = archive.infolist()
        names = [item.filename for item in files]
        if len(files) != 9 or len(set(names)) != len(names):
            raise ValueError("Unexpected check bundle contents")
        if sum(item.file_size for item in files) > 1024 * 1024 * 1024:
            raise ValueError("Check bundle exceeds size limit")
        for item in files:
            if (not re.fullmatch(r"[a-zA-Z0-9_.-]+", item.filename)
                    or item.is_dir() or stat.S_ISLNK(item.external_attr >> 16)
                    or item.file_size > 512 * 1024 * 1024):
                raise ValueError("Invalid file in check bundle")
        metadata = archive.getinfo("checks.json")
        if metadata.file_size > 16384:
            raise ValueError("Check manifest exceeds size limit")
        manifest = json.loads(archive.read(metadata))
        if (manifest.get("schema") != 1 or manifest.get("os") != "windows"
                or manifest.get("arch") != "x64" or manifest.get("source_dirty") is not False
                or not re.fullmatch(r"[a-f0-9]{40}", manifest.get("source_revision", ""))
                or not re.fullmatch(r"\d+\.\d+\.\d+", manifest.get("version", ""))):
            raise ValueError("Invalid check manifest")
        entries = manifest.get("files", [])
        expected_names = {"sentinel.exe", f"Sentinel-Atlas-{manifest['version']}-windows-x64.exe"}
        expected_names.update(f"test-{suite}.exe" for suite in SUITES)
        if ({entry.get("file") for entry in entries} != expected_names
                or len(entries) != len(expected_names) or set(names) != expected_names | {"checks.json"}):
            raise ValueError("Incomplete check bundle")
        for entry in entries:
            info = archive.getinfo(entry["file"])
            if type(entry.get("bytes")) is not int or entry["bytes"] <= 0 or info.file_size != entry["bytes"]:
                raise ValueError("Check file size mismatch")
        # Validate the entire layout before creating any files.
        for entry in entries:
            target = destination / entry["file"]
            with archive.open(entry["file"]) as source, target.open("xb") as output:
                while chunk := source.read(1024 * 1024):
                    output.write(chunk)
            if digest(target) != entry.get("sha256"):
                raise ValueError("Check file checksum mismatch")
    return manifest


def smoke_server(binary):
    with tempfile.TemporaryDirectory(prefix="sentinel server check ") as temporary:
        root = Path(temporary)
        (root / "config").mkdir()
        (root / "config/seeds.txt").touch()
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        with (root / "server.log").open("wb") as log:
            process = subprocess.Popen([str(binary), "--root", str(root), "serve", "--watch",
                "--allow-empty-seeds", "--shutdown-on-stdin", "--port", str(port)],
                stdin=subprocess.PIPE, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise RuntimeError("Packaged server exited before becoming ready")
                    try:
                        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/status", timeout=1) as response:
                            state = json.load(response)
                        if state.get("project") != "Sentinel Atlas" or state.get("assets") != []:
                            raise RuntimeError("Unexpected initial server state")
                        break
                    except OSError:
                        time.sleep(0.1)
                else:
                    raise RuntimeError("Packaged server did not become ready")
                process.stdin.close()
                if process.wait(timeout=10) != 0:
                    raise RuntimeError("Packaged server did not stop cleanly")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
                process.stdin.close()


def suite(binary, env, *arguments):
    with tempfile.TemporaryFile() as log:
        result = subprocess.run([str(binary), *arguments, "--test-threads=1"],
            env=env, stdout=log, stderr=subprocess.STDOUT, timeout=300)
        log.seek(0)
        output = log.read(4 * 1024 * 1024).decode(errors="replace")
    print(output, flush=True)
    match = re.search(r"test result: ok\. (\d+) passed; 0 failed;", output)
    if result.returncode or not match or int(match[1]) == 0:
        raise RuntimeError(f"Test suite failed or ran no tests: {binary.name}")
    return int(match[1])


def check(bundle, expected, report):
    if sys.platform != "win32" or os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise RuntimeError("Installer checks require a disposable GitHub-hosted Windows runner")
    with tempfile.TemporaryDirectory(prefix="sentinel package checks ") as temporary:
        root = Path(temporary)
        manifest = unpack(bundle, expected, root)
        env = dict(os.environ, SENTINEL_TEST_BACKEND=str(root / "sentinel.exe"))
        for key in ("GH_TOKEN", "GITHUB_TOKEN", "ACTIONS_RUNTIME_TOKEN"):
            env.pop(key, None)
        tests = {name: suite(root / f"test-{name}.exe", env) for name in sorted(SUITES)}
        tests["desktop-server-lifecycle"] = suite(root / "test-desktop.exe", env,
            "included_server_creates_private_empty_workspace", "--ignored")
        smoke_server(root / "sentinel.exe")
        name = f"Sentinel-Atlas-{manifest['version']}-windows-x64.exe"
        installed = root / "installed app"
        # NSIS requires /D and _?= to be last and unquoted, even with spaces.
        command = subprocess.list2cmdline([str(root / name), "/S"])
        subprocess.run(f"{command} /D={installed}", check=True, env=env, timeout=180)
        try:
            smoke_server(installed / "backend/sentinel.exe")
            if digest(installed / "backend/sentinel.exe") != digest(root / "sentinel.exe"):
                raise RuntimeError("Installed server differs from the checked server")
        finally:
            command = subprocess.list2cmdline([str(installed / "uninstall.exe"), "/S"])
            subprocess.run(f"{command} _?={installed}", check=True, env=env, timeout=60)
        if (installed / "backend/sentinel.exe").exists():
            raise RuntimeError("Uninstaller left the server installed")
        package = next(entry for entry in manifest["files"] if entry["file"] == name)
        result = {"schema": 1, "result": "passed", "os": "windows", "arch": "x64",
            "source_revision": manifest["source_revision"], "bundle_sha256": expected,
            "tests": tests, "installer": "passed", "package": package,
            "run_id": os.environ["GITHUB_RUN_ID"], "repository": os.environ["GITHUB_REPOSITORY"],
            "verifier_revision": os.environ["GITHUB_SHA"]}
        report.write_text(json.dumps(result, indent=2) + "\n")
        print("Windows package checks passed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    check(args.bundle.resolve(), args.sha256, args.report)
