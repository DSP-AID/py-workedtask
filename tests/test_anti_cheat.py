"""Unit tests for Javelin Anti-Cheat module and integrity verification."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

# Ensure py-workedtask repository root is in sys.path
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import anti_cheat


class TestComputeSha256(unittest.TestCase):
    """Test SHA-256 calculation logic."""

    def test_compute_sha256_known_content(self) -> None:
        content = b"Javelin AntiCheat Integrity Test Payload\n"
        expected = hashlib.sha256(content).hexdigest()
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(content)
            tmp_path = Path(tmp.name)
        try:
            actual = anti_cheat.compute_sha256(tmp_path)
            self.assertEqual(actual, expected)
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_compute_sha256_missing_file(self) -> None:
        with self.assertRaises(FileNotFoundError):
            anti_cheat.compute_sha256(Path("non_existent_file_12345.xyz"))


class TestIntegrityCheck(unittest.TestCase):
    """Test script self-integrity verification against JAVELIN_EXPECTED_SHA256."""

    def setUp(self) -> None:
        self.original_env = os.environ.get(anti_cheat.ENV_EXPECTED_SHA256)

    def tearDown(self) -> None:
        if self.original_env is not None:
            os.environ[anti_cheat.ENV_EXPECTED_SHA256] = self.original_env
        else:
            os.environ.pop(anti_cheat.ENV_EXPECTED_SHA256, None)

    def test_skipped_when_env_unset(self) -> None:
        os.environ.pop(anti_cheat.ENV_EXPECTED_SHA256, None)
        self.assertTrue(anti_cheat.check_self_integrity())

    def test_skipped_when_env_empty(self) -> None:
        os.environ[anti_cheat.ENV_EXPECTED_SHA256] = "   "
        self.assertTrue(anti_cheat.check_self_integrity())

    def test_passes_with_matching_hash(self) -> None:
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as tmp:
            tmp.write("#!/usr/bin/env python\nprint('Hello Javelin')\n")
            tmp_path = Path(tmp.name)
        try:
            real_hash = anti_cheat.compute_sha256(tmp_path)
            os.environ[anti_cheat.ENV_EXPECTED_SHA256] = real_hash
            self.assertTrue(anti_cheat.check_self_integrity(script_path=tmp_path))
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_passes_case_insensitive(self) -> None:
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as tmp:
            tmp.write("Payload 42\n")
            tmp_path = Path(tmp.name)
        try:
            real_hash = anti_cheat.compute_sha256(tmp_path)
            os.environ[anti_cheat.ENV_EXPECTED_SHA256] = real_hash.upper()
            self.assertTrue(anti_cheat.check_self_integrity(script_path=tmp_path))
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_fails_on_hash_mismatch(self) -> None:
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as tmp:
            tmp.write("Original content\n")
            tmp_path = Path(tmp.name)
        try:
            os.environ[anti_cheat.ENV_EXPECTED_SHA256] = "a" * 64
            self.assertFalse(anti_cheat.check_self_integrity(script_path=tmp_path))
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_fails_when_file_tampered(self) -> None:
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as tmp:
            tmp.write("Initial script code\n")
            tmp_path = Path(tmp.name)
        try:
            baseline_hash = anti_cheat.compute_sha256(tmp_path)
            os.environ[anti_cheat.ENV_EXPECTED_SHA256] = baseline_hash

            # Simulate malicious tampering
            with open(tmp_path, "a", encoding="utf-8") as f:
                f.write("# Injected tampering payload\n")

            self.assertFalse(anti_cheat.check_self_integrity(script_path=tmp_path))
        finally:
            tmp_path.unlink(missing_ok=True)


class TestDebuggerDetection(unittest.TestCase):
    """Test debugger check functionality."""

    def test_debugger_detected_when_sys_trace_active(self) -> None:
        def dummy_trace(frame, event, arg):
            return dummy_trace

        with patch("sys.gettrace", return_value=dummy_trace):
            self.assertTrue(anti_cheat.check_debugger())


class TestSuspiciousProcessDetection(unittest.TestCase):
    """Test suspicious process detection."""

    def test_suspicious_process_detected(self) -> None:
        mock_processes = ["svchost.exe", "explorer.exe", "cheatengine.exe"]
        with patch("anti_cheat._get_running_process_names", return_value=mock_processes):
            self.assertTrue(anti_cheat.check_suspicious_processes())

    def test_suspicious_process_not_detected_clean_environment(self) -> None:
        mock_processes = ["svchost.exe", "explorer.exe", "python.exe"]
        with patch("anti_cheat._get_running_process_names", return_value=mock_processes):
            self.assertFalse(anti_cheat.check_suspicious_processes())


class TestRunChecksAndCLI(unittest.TestCase):
    """Test end-to-end run_checks and CLI invocation."""

    def test_run_checks_clean_environment(self) -> None:
        with patch("anti_cheat.check_debugger", return_value=False), \
             patch("anti_cheat.check_suspicious_processes", return_value=False):
            code = anti_cheat.run_checks(expected_hash="")
            self.assertEqual(code, anti_cheat.EXIT_OK)

    def test_run_checks_mismatch_returns_exit_integrity_failure(self) -> None:
        with patch("anti_cheat.check_debugger", return_value=False), \
             patch("anti_cheat.check_suspicious_processes", return_value=False):
            code = anti_cheat.run_checks(expected_hash="0" * 64)
            self.assertEqual(code, anti_cheat.EXIT_INTEGRITY_FAILURE)

    def test_cli_hash_file_argument(self) -> None:
        script_path = REPO_ROOT / "anti_cheat.py"
        with patch("sys.stdout"):
            exit_code = anti_cheat.main(["--hash-file", str(script_path)])
            self.assertEqual(exit_code, anti_cheat.EXIT_OK)

    def test_cli_subprocess_guarded_exit_on_tamper(self) -> None:
        script_file = REPO_ROOT / "anti_cheat.py"
        env = os.environ.copy()
        env[anti_cheat.ENV_EXPECTED_SHA256] = "0" * 64

        proc = subprocess.run(
            [sys.executable, str(script_file)],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, anti_cheat.EXIT_INTEGRITY_FAILURE)
        self.assertIn("Integrity check failed", proc.stderr)
        self.assertIn("starting checks", proc.stdout)

    def test_cli_subprocess_clean_run(self) -> None:
        script_file = REPO_ROOT / "anti_cheat.py"
        real_hash = anti_cheat.compute_sha256(script_file)
        env = os.environ.copy()
        env[anti_cheat.ENV_EXPECTED_SHA256] = real_hash

        proc = subprocess.run(
            [sys.executable, str(script_file)],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, anti_cheat.EXIT_OK)
        self.assertIn("All clear. Continue.", proc.stdout)


if __name__ == "__main__":
    unittest.main()
