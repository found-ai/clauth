#!/usr/bin/env python3
"""Offline release checks; installers write only inside temporary directories."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("validate_release", ROOT / "scripts/validate-release.py")
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class ReleaseTests(unittest.TestCase):
    def test_current_tag_matches_binary_and_plugin(self):
        VALIDATOR.validate("v0.17.0-found.2", ROOT)

    def test_wrong_tags_are_refused(self):
        for tag in ["v0.17.0", "v0.17.0-found.1", "v0.17.0-found.3", "v0.17.0-found.0", "v0.17.0-rc1", "0.17.0-found.1", "vgarbage"]:
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                VALIDATOR.validate(tag, ROOT)

    def test_plugin_mismatch_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Cargo.toml").write_text('[package]\nversion = "0.17.0-found.1"\n')
            plugin = root / "plugins/.claude-plugin/plugin.json"
            plugin.parent.mkdir(parents=True)
            plugin.write_text(json.dumps({"version": "0.17.0"}))
            with self.assertRaises(ValueError):
                VALIDATOR.validate("v0.17.0-found.1", root)

    def install(self, mode, args=()):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools = root / "tools"
            tools.mkdir()
            target = root / "installed"
            target.mkdir()
            binary = target / "clauth"
            binary.write_text("previous binary")
            asset = root / "asset"
            payload = b'#!/bin/sh\nprintf "%s\\n" "$*" >> "$TEST_HEAL_LOG"\n'
            asset.write_bytes(payload)
            sums = root / "sums"
            digest = hashlib.sha256(payload).hexdigest() if mode != "corrupt" else "0" * 64
            sums.write_text(f"{digest}  clauth-macos-aarch64\n")
            stubs = {
                "uname": '#!/bin/sh\ncase "$1" in -s) echo Darwin;; -m) echo arm64;; esac\n',
                "cargo": '#!/bin/sh\necho "unexpected cargo fallback" >&2\nexit 90\n',
                "curl": '''#!/bin/sh
url=""; dest=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    https://*) url="$1"; shift;;
    -o) dest="$2"; shift 2;;
    *) shift;;
  esac
done
printf '%s\n' "$url" >> "$TEST_URL_LOG"
case "$url" in
  */sha256sums.txt)
    [ "$TEST_MODE" != missing ] || exit 22
    cp "$TEST_SUMS" "$dest";;
  */clauth-macos-aarch64) cp "$TEST_ASSET" "$dest";;
  *) exit 91;;
esac
''',
            }
            for name, text in stubs.items():
                path = tools / name
                path.write_text(text)
                path.chmod(0o755)
            env = os.environ | {
                "PATH": f"{tools}:{os.environ['PATH']}",
                "CLAUTH_INSTALL_DIR": str(target),
                "TEST_ASSET": str(asset),
                "TEST_SUMS": str(sums),
                "TEST_MODE": mode,
                "TEST_URL_LOG": str(root / "urls"),
                "TEST_HEAL_LOG": str(root / "heal"),
            }
            result = subprocess.run(["bash", str(ROOT / "install.sh"), *args], env=env, capture_output=True, text=True)
            urls = (root / "urls").read_text().splitlines()
            base = "https://github.com/found-ai/clauth/releases/download/v0.17.0-found.2/"
            self.assertEqual(urls, [base + "clauth-macos-aarch64", base + "sha256sums.txt"])
            if mode == "ok":
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(binary.read_bytes(), payload)
                self.assertEqual((root / "heal").read_text(), "self-heal\n")
            else:
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(binary.read_text(), "previous binary")
                self.assertFalse((root / "heal").exists())

    def test_installer_uses_found_even_with_cargo_installed(self):
        self.install("ok")

    def test_nocargo_compatibility(self):
        self.install("ok", ["--nocargo"])

    def test_bad_checksum_preserves_previous_binary(self):
        self.install("corrupt")

    def test_missing_checksum_preserves_previous_binary(self):
        self.install("missing")


if __name__ == "__main__":
    unittest.main()
