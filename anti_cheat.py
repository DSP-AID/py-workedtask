#!/usr/bin/env python3
"""Javelin Anti-Cheat - Minimal Anti-Cheat guards and script integrity verifier.

Features:
- Debugger detection (Windows IsDebuggerPresent / PEB BeingDebugged & sys.gettrace)
- Suspicious process detection (Cheat Engine, x64dbg, OllyDbg, etc.)
- Script self-integrity verification (SHA-256 hash compared to JAVELIN_EXPECTED_SHA256)
"""

from __future__ import annotations

import argparse
import csv
import ctypes
import hashlib
import hmac
import os
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

# --- Constants & Guarded Exit Codes ---
kTag: str = "[Javelin AntiCheat] "
ENV_EXPECTED_SHA256: str = "JAVELIN_EXPECTED_SHA256"

EXIT_OK: int = 0
EXIT_DEBUGGER_DETECTED: int = 0xDEB       # 3563
EXIT_SUSPICIOUS_PROCESS: int = 0xBAD      # 2989
EXIT_INTEGRITY_FAILURE: int = 0x54A       # 1354 (replaces non-standard 0xCRC)

SUSPICIOUS_PROCESSES: tuple[str, ...] = (
    "cheatengine.exe",
    "ollydbg.exe",
    "x64dbg.exe",
    "httpdebuggerui.exe",
    "ida.exe",
    "ida64.exe",
    "scylla.exe",
    "processhacker.exe",
)


def compute_sha256(file_path: str | Path, chunk_size: int = 65536) -> str:
    """Compute the SHA-256 hexadecimal digest of a file in streaming chunks.

    Args:
        file_path: Path to the target file.
        chunk_size: Read buffer size in bytes (defaults to 64 KB).

    Returns:
        Lowercase hexadecimal SHA-256 digest string.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest().lower()


def check_debugger() -> bool:
    """Detect if the current process is running under an active debugger.

    Checks:
    1. Python execution trace (sys.gettrace()).
    2. Windows API IsDebuggerPresent via ctypes.windll.kernel32.
    3. Linux /proc/self/status TracerPid if running on POSIX.

    Returns:
        True if an active debugger is detected, False otherwise.
    """
    # 1. Python trace hook
    if sys.gettrace() is not None:
        return True

    # 2. Windows native IsDebuggerPresent
    if sys.platform == "win32":
        try:
            kernel32 = ctypes.windll.kernel32
            if kernel32.IsDebuggerPresent() != 0:
                return True
        except (AttributeError, OSError):
            pass

    # 3. POSIX TracerPid check
    elif sys.platform.startswith("linux"):
        status_path = Path("/proc/self/status")
        if status_path.is_file():
            try:
                for line in status_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                    if line.startswith("TracerPid:"):
                        pid = int(line.split(":", 1)[1].strip())
                        if pid != 0:
                            return True
            except (ValueError, OSError):
                pass

    return False


def _get_running_process_names() -> list[str]:
    """Retrieve lowercase names of currently active processes without external dependencies."""
    names: list[str] = []

    # Optional psutil acceleration if installed
    try:
        import psutil  # type: ignore
        for proc in psutil.process_iter(["name"]):
            try:
                pname = proc.info.get("name")
                if pname:
                    names.append(pname.lower())
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return names
    except ImportError:
        pass

    # Platform native fallback
    if sys.platform == "win32":
        try:
            # tasklist /FO CSV /NH outputs CSV without headers
            out = subprocess.check_output(
                ["tasklist", "/FO", "CSV", "/NH"],
                stderr=subprocess.DEVNULL,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
            reader = csv.reader(out.splitlines())
            for row in reader:
                if row:
                    names.append(row[0].strip().lower())
        except (subprocess.SubprocessError, OSError):
            pass
    else:
        try:
            out = subprocess.check_output(["ps", "-A", "-o", "comm="], stderr=subprocess.DEVNULL, text=True)
            for line in out.splitlines():
                line = line.strip().lower()
                if line:
                    names.append(line)
        except (subprocess.SubprocessError, OSError):
            pass

    return names


def check_suspicious_processes(suspicious_list: Sequence[str] = SUSPICIOUS_PROCESSES) -> bool:
    """Scan running processes for known cheat and debugging software.

    Args:
        suspicious_list: Iterable of suspicious process names to check against.

    Returns:
        True if any prohibited process is detected, False otherwise.
    """
    prohibited_set = {p.lower() for p in suspicious_list}
    running = _get_running_process_names()
    for name in running:
        if name in prohibited_set:
            return True
    return False


def check_self_integrity(
    script_path: str | Path | None = None,
    expected_hash: str | None = None,
) -> bool:
    """Verify the SHA-256 integrity of the script against the expected digest.

    If expected_hash is not explicitly passed, it is read from the
    JAVELIN_EXPECTED_SHA256 environment variable. If the environment variable is
    unset or empty, the check is skipped (opt-in verification) and returns True.

    Args:
        script_path: Path of the script to check. Defaults to this module file.
        expected_hash: Expected SHA-256 hex string.

    Returns:
        True if hash matches or if check is skipped, False on integrity mismatch.
    """
    if expected_hash is None:
        expected_hash = os.environ.get(ENV_EXPECTED_SHA256)

    # Opt-in: if unset or empty, integrity check is skipped
    if not expected_hash or not expected_hash.strip():
        return True

    target_path = Path(script_path) if script_path else Path(__file__).resolve()
    try:
        actual_hash = compute_sha256(target_path)
    except OSError:
        return False

    clean_expected = expected_hash.strip().lower()
    return hmac.compare_digest(actual_hash, clean_expected)


# CamelCase aliases matching C++ function names
checkDebugger = check_debugger
checkSuspiciousProcesses = check_suspicious_processes
checkSelfIntegrity = check_self_integrity


def run_checks(
    script_path: str | Path | None = None,
    expected_hash: str | None = None,
) -> int:
    """Execute all anti-cheat guards in sequence.

    Returns:
        EXIT_OK (0) on success, or the corresponding EXIT_* guarded code on failure.
    """
    print(f"{kTag}starting checks...")

    if check_debugger():
        print(f"{kTag}Debugger detected. Exiting.", file=sys.stderr)
        return EXIT_DEBUGGER_DETECTED

    if check_suspicious_processes():
        print(f"{kTag}Suspicious process detected. Exiting.", file=sys.stderr)
        return EXIT_SUSPICIOUS_PROCESS

    if not check_self_integrity(script_path, expected_hash):
        print(f"{kTag}Integrity check failed (SHA-256 mismatch). Exiting.", file=sys.stderr)
        return EXIT_INTEGRITY_FAILURE

    print(f"{kTag}All clear. Continue.")
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point for Javelin Anti-Cheat monitor."""
    parser = argparse.ArgumentParser(
        description="Javelin Anti-Cheat — Minimal Anti-Cheat guards and SHA-256 integrity verifier."
    )
    parser.add_argument(
        "--hash-file",
        type=Path,
        metavar="PATH",
        help="Compute and display the SHA-256 digest of a target file and exit.",
    )
    parser.add_argument(
        "--expected",
        type=str,
        metavar="HEX",
        help="Explicit expected SHA-256 hash (overrides JAVELIN_EXPECTED_SHA256 env var).",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Only verify script integrity (skip debugger and process checks).",
    )

    args = parser.parse_args(argv)

    if args.hash_file:
        try:
            digest = compute_sha256(args.hash_file)
            print(f"SHA256({args.hash_file}) = {digest}")
            return EXIT_OK
        except OSError as e:
            print(f"Error computing hash: {e}", file=sys.stderr)
            return 1

    if args.verify_only:
        passed = check_self_integrity(expected_hash=args.expected)
        if not passed:
            print(f"{kTag}Integrity check failed (SHA-256 mismatch). Exiting.", file=sys.stderr)
            return EXIT_INTEGRITY_FAILURE
        print(f"{kTag}Integrity check verified successfully.")
        return EXIT_OK

    return run_checks(expected_hash=args.expected)


if __name__ == "__main__":
    sys.exit(main())
