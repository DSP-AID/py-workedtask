"""Javelin anti-cheat module (Python implementation).

Features:
  - Debugger detection (ctypes IsDebuggerPresent on Windows, ptrace on Linux).
  - Suspicious process scan (cheat engines / debuggers by image name).
  - Self-integrity verification: SHA-256 of the running script file compared
    against the JAVELIN_EXPECTED_SHA256 environment variable.

Integrity acceptance criteria:
  - Non-matching hash MUST result in a guarded exit (error message + code 3).
  - Matching hash or unset/empty env var passes without enforcement.
"""
from __future__ import annotations

import ctypes
import hashlib
import os
import platform
import sys

EXIT_DEBUGGER = 1
EXIT_SUSPICIOUS_PROCESS = 2
EXIT_INTEGRITY_FAILURE = 3

# Image names (lowercase, no .exe) whose presence means tampering/reversing tools.
SUSPICIOUS_PROCESSES = (
    "cheatengine",
    "cheatengine-x86_64",
    "ollydbg",
    "x64dbg",
    "x32dbg",
    "httpdebuggerui",
    "ida",
    "ida64",
    "scylla",
    "processhacker",
)

_TAG = "[Javelin AntiCheat] "


def sha256_file(path: str) -> str:
    """SHA-256 hex digest of a file, streamed in chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def self_path() -> str:
    """Absolute path of the running script/module file."""
    return os.path.realpath(globals().get("__file__") or sys.argv[0])


# --- Debugger detection ---

def check_debugger() -> bool:
    """Best-effort native debugger detection for the current process."""
    if sys.gettrace() is not None:  # managed tracer (pdb/sys.settrace)
        return True

    system = platform.system()
    if system == "Windows":
        try:
            kernel32 = ctypes.windll.kernel32
            kernel32.IsDebuggerPresent.restype = ctypes.c_bool
            return bool(kernel32.IsDebuggerPresent())
        except (AttributeError, OSError):
            return False

    if system == "Linux":
        # PTRACE_TRACEME fails (-1) if a debugger already traces us.
        try:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            libc.ptrace.restype = ctypes.c_long
            libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long,
                                    ctypes.c_void_p, ctypes.c_void_p]
            if libc.ptrace(0, 0, None, None) == -1:  # PTRACE_TRACEME
                return True
            libc.ptrace(17, 0, None, None)  # PTRACE_DETACH: restore state
            return False
        except OSError:
            return False

    return False  # macOS/other: not implemented


# --- Suspicious process scan ---

def _windows_process_names() -> list[str]:
    TH32CS_SNAPPROCESS = 0x00000002
    kernel32 = ctypes.windll.kernel32

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", ctypes.c_uint32),
            ("cntUsage", ctypes.c_uint32),
            ("th32ProcessID", ctypes.c_uint32),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", ctypes.c_uint32),
            ("cntThreads", ctypes.c_uint32),
            ("th32ParentProcessID", ctypes.c_uint32),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", ctypes.c_uint32),
            ("szExeFile", ctypes.c_wchar * 260),
        ]

    kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap is None or snap == ctypes.c_void_p(-1).value:
        return []

    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
    names: list[str] = []
    try:
        if kernel32.Process32FirstW(snap, ctypes.byref(entry)):
            while True:
                names.append(entry.szExeFile)
                if not kernel32.Process32NextW(snap, ctypes.byref(entry)):
                    break
    finally:
        kernel32.CloseHandle(snap)
    return names


def iter_process_names() -> list[str]:
    """Image names of all running processes (empty list if unsupported)."""
    system = platform.system()
    if system == "Windows":
        return _windows_process_names()
    if system == "Linux":
        names: list[str] = []
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open(f"/proc/{pid}/comm", "rb") as f:
                    names.append(f.read().decode(errors="ignore").strip())
            except OSError:
                continue
        return names
    return []


def find_suspicious_process(proc_names: list[str] | None = None) -> str | None:
    """Return first process name matching the blocklist, else None.

    proc_names may be injected (e.g. by tests); defaults to live enumeration.
    Matching is case-insensitive and ignores a trailing .exe.
    """
    names = iter_process_names() if proc_names is None else proc_names
    for name in names:
        base = name.lower().removesuffix(".exe")
        if base in SUSPICIOUS_PROCESSES:
            return name
    return None


# --- Self-integrity verification ---

def check_self_integrity(expected_sha256: str | None = None,
                         path: str | None = None) -> bool:
    """True when integrity is OK or enforcement is off.

    Expected value resolution order: explicit argument, then env var
    JAVELIN_EXPECTED_SHA256. Unset/empty means "no enforcement" -> True.
    """
    expected = (expected_sha256 if expected_sha256 is not None
                else os.environ.get("JAVELIN_EXPECTED_SHA256"))
    if not expected or not expected.strip():
        return True
    actual = sha256_file(path if path is not None else self_path())
    return actual == expected.strip().lower()


def enforce_self_integrity() -> None:
    """Guarded exit (code 3) when the running script hash does not match."""
    if not check_self_integrity():
        print(f"{_TAG}Integrity check failed (SHA-256 mismatch). Exiting.",
              file=sys.stderr)
        sys.exit(EXIT_INTEGRITY_FAILURE)


def main() -> int:
    print(f"{_TAG}starting checks...")

    if check_debugger():
        print(f"{_TAG}Debugger detected. Exiting.", file=sys.stderr)
        return EXIT_DEBUGGER

    bad = find_suspicious_process()
    if bad is not None:
        print(f"{_TAG}Suspicious process detected: {bad}. Exiting.",
              file=sys.stderr)
        return EXIT_SUSPICIOUS_PROCESS

    enforce_self_integrity()  # exits with code 3 on mismatch

    print(f"{_TAG}All clear. Continue.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
