"""Pytest suite for the Javelin Python anti-cheat module (anticheat.py).

Covers: integrity pass/mismatch/unset, guarded exit code 3, sha256 helper,
suspicious process detection interface, debugger detection interface.
"""
import hashlib
import os
import platform
import subprocess
import sys
from pathlib import Path

import anticheat
import pytest

REPO_DIR = Path(__file__).resolve().parent
SELF_HASH = anticheat.sha256_file(anticheat.__file__)


# --- SHA-256 helper ---

def test_sha256_file_known_vector(tmp_path):
    f = tmp_path / "hello.txt"
    f.write_bytes(b"hello")
    assert anticheat.sha256_file(str(f)) == (
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    )


def test_self_hash_matches_raw_recompute():
    assert SELF_HASH == hashlib.sha256(
        Path(anticheat.__file__).read_bytes()
    ).hexdigest()


# --- Integrity verification (acceptance criteria) ---

def test_matching_sha256_passes(monkeypatch):
    monkeypatch.setenv("JAVELIN_EXPECTED_SHA256", SELF_HASH)
    assert anticheat.check_self_integrity() is True
    anticheat.enforce_self_integrity()  # must not raise SystemExit


def test_mismatched_sha256_guarded_exit(monkeypatch, capsys):
    monkeypatch.setenv("JAVELIN_EXPECTED_SHA256", "0" * 64)
    assert anticheat.check_self_integrity() is False
    with pytest.raises(SystemExit) as exc:
        anticheat.enforce_self_integrity()
    assert exc.value.code == anticheat.EXIT_INTEGRITY_FAILURE == 3
    captured = capsys.readouterr()
    assert "Integrity check failed" in captured.err
    assert captured.out == ""


def test_unset_env_var_passes_without_enforcement(monkeypatch):
    monkeypatch.delenv("JAVELIN_EXPECTED_SHA256", raising=False)
    assert anticheat.check_self_integrity() is True
    anticheat.enforce_self_integrity()  # no enforcement -> plain pass


def test_blank_env_var_treated_as_unset(monkeypatch):
    monkeypatch.setenv("JAVELIN_EXPECTED_SHA256", "   ")
    assert anticheat.check_self_integrity() is True


def test_check_self_integrity_explicit_arguments(tmp_path):
    f = tmp_path / "app.py"
    f.write_bytes(b"print(1)")
    digest = hashlib.sha256(b"print(1)").hexdigest()
    # Explicit expected wins over env resolution; case-insensitive compare.
    assert anticheat.check_self_integrity(expected_sha256=digest, path=str(f)) is True
    assert anticheat.check_self_integrity(expected_sha256=digest.upper(), path=str(f)) is True
    assert anticheat.check_self_integrity(expected_sha256="ff" * 32, path=str(f)) is False


def test_main_propagates_integrity_exit(monkeypatch):
    monkeypatch.setattr(anticheat, "check_debugger", lambda: False)
    monkeypatch.setattr(anticheat, "find_suspicious_process", lambda proc_names=None: None)
    monkeypatch.setenv("JAVELIN_EXPECTED_SHA256", "deadbeef")
    with pytest.raises(SystemExit) as exc:
        anticheat.main()
    assert exc.value.code == 3


# --- Suspicious process detection interface ---

@pytest.mark.parametrize("name", [
    "cheatengine.exe",
    "CheatEngine-X86_64.EXE",
    "x64dbg.exe",
    "ollydbg.exe",
    "ProcessHacker.exe",
])
def test_find_suspicious_process_detects_known_tools(name):
    assert anticheat.find_suspicious_process([name]) == name


def test_find_suspicious_process_clean_list_returns_none():
    assert anticheat.find_suspicious_process(
        ["python.exe", "chrome.exe", "svchost"]
    ) is None


def test_iter_process_names_interface():
    names = anticheat.iter_process_names()
    assert isinstance(names, list)
    assert all(isinstance(n, str) for n in names)
    if platform.system() in ("Windows", "Linux"):
        me = Path(sys.executable).name.lower()
        assert any(n.lower() == me for n in names), "current interpreter must be visible"


# --- Debugger detection interface ---

def test_check_debugger_returns_bool():
    assert isinstance(anticheat.check_debugger(), bool)


def test_check_debugger_false_in_clean_environment():
    assert sys.gettrace() is None  # no tracer under plain pytest
    assert anticheat.check_debugger() is False


# --- Subprocess end-to-end (real guarded exit codes) ---

def _run_snippet(env_extra):
    env = dict(os.environ)
    env.pop("JAVELIN_EXPECTED_SHA256", None)
    env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-c", "import anticheat; anticheat.enforce_self_integrity()"],
        cwd=REPO_DIR, env=env, capture_output=True, text=True, timeout=30,
        check=False,  # guarded exit codes are asserted by the caller
    )


def test_subprocess_mismatch_exits_with_code_3():
    proc = _run_snippet({"JAVELIN_EXPECTED_SHA256": "1" * 64})
    assert proc.returncode == 3
    assert "Integrity check failed" in proc.stderr


def test_subprocess_unset_passes():
    proc = _run_snippet({})
    assert proc.returncode == 0


def test_subprocess_matching_hash_passes():
    proc = _run_snippet({"JAVELIN_EXPECTED_SHA256": SELF_HASH})
    assert proc.returncode == 0
