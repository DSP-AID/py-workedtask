# Javelin Anti-Cheat (py-workedtask)

Minimal anti-cheat guards for shipped builds: debugger detection, suspicious
process scan, and **integrity verification** (detects a tampered executable or
script). See issue [#4](https://github.com/javelin-anticheat/py-workedtask/issues/4).

## Files

| File | Description |
|------|-------------|
| `AntiCheat.cpp` | C++ (Windows) guard: debugger check, process scan, CRC32 + optional SHA-256 self-integrity of the running `.exe` |
| `anticheat.py` | Python module: debugger check (Windows/Linux), suspicious process scan, SHA-256 self-integrity of the running script |
| `test_anticheat.py` | Pytest suite for the Python module |

## C++ usage

### Plain build (no integrity enforcement)

```bat
cl /EHsc AntiCheat.cpp /Fe:javelin_guard.exe
```

### CRC32 self-integrity (build-time constant)

The CRC32 check is active only when `JAVELIN_EXPECTED_CRC32` is defined and
non-zero (`#ifndef` fallback is `0u` = check disabled):

```bat
cl /EHsc AntiCheat.cpp /DJAVELIN_EXPECTED_CRC32=0x12345678 /Fe:javelin_guard.exe
```

Compute the expected CRC32 of the reference binary with Python stdlib:

```bat
python -c "import zlib,sys;print(hex(zlib.crc32(open(sys.argv[1],'rb').read())))" javelin_guard.exe
```

### SHA-256 self-integrity (build-time constant)

Define `JAVELIN_EXPECTED_SHA256` as a quoted hex string; when it is not
defined, the SHA-256 check is compiled out entirely. On MSVC the inner quotes
must be escaped:

```bat
cl /EHsc AntiCheat.cpp /DJAVELIN_EXPECTED_SHA256="\"<64-hex-digits>\"" /Fe:javelin_guard.exe
:: or, from PowerShell:
cl /EHsc AntiCheat.cpp '/DJAVELIN_EXPECTED_SHA256="\"<64-hex-digits>\""' /Fe:javelin_guard.exe
```

Compute the expected SHA-256 of the reference binary:

```bat
certutil -hashfile javelin_guard.exe SHA256
:: or
(Get-FileHash javelin_guard.exe -Algorithm SHA256).Hash.ToLower()
```

### C++ exit codes

| Code | Meaning |
|------|---------|
| `0` | All checks passed |
| `0xDEB` | Debugger detected |
| `0xBAD` | Suspicious process detected |
| `0x103` | Integrity check failed (CRC32 or SHA-256 mismatch) — guarded exit |

> Known limitation: embedding the expected hash into the binary changes the
> file bytes, so the constant must be taken from a staging build and injected
> via a final packaging/link step (or kept as a separate manifest) in real
> deployments. The build-time macro pattern is kept here as specified.

## Python usage

Run the guard alongside your application:

```python
import anticheat

anticheat.enforce_self_integrity()  # call early at startup
```

Or as a standalone check:

```bat
python anticheat.py
```

### Integrity verification via `JAVELIN_EXPECTED_SHA256`

The module computes the SHA-256 of the running script file (`__file__` /
`sys.argv[0]`) and compares it to the `JAVELIN_EXPECTED_SHA256` environment
variable:

- **Variable unset or empty** → no enforcement, check passes.
- **Hash matches** (case-insensitive) → check passes.
- **Hash does not match** → error message on stderr and **guarded exit with code 3**.

Compute the expected hash of your entry script:

```bat
certutil -hashfile myapp.py SHA256
:: or
python -c "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" myapp.py
```

Set the variable:

```bat
:: cmd (current session)
set JAVELIN_EXPECTED_SHA256=a1b2c3...

:: PowerShell (current session)
$env:JAVELIN_EXPECTED_SHA256 = "a1b2c3..."

:: Persist for the whole machine/user
setx JAVELIN_EXPECTED_SHA256 "a1b2c3..."
```

Example — tampered script detected:

```bat
set JAVELIN_EXPECTED_SHA256=deadbeef
python anticheat.py
:: [Javelin AntiCheat] Integrity check failed (SHA-256 mismatch). Exiting.
:: errorlevel = 3
```

### Python exit codes (`python anticheat.py`)

| Code | Meaning |
|------|---------|
| `0` | All checks passed (or integrity not enforced) |
| `1` | Debugger detected |
| `2` | Suspicious process detected |
| `3` | Integrity check failed (SHA-256 mismatch) — guarded exit |

### Detection interfaces

```python
anticheat.check_debugger()               # bool: native debugger attached?
anticheat.find_suspicious_process()      # first bad process name or None
anticheat.iter_process_names()           # live process image names
anticheat.sha256_file(path)              # SHA-256 hex digest of a file
```

Blocklisted processes (lowercase, `.exe` stripped before compare):
`cheatengine`, `cheatengine-x86_64`, `ollydbg`, `x64dbg`, `x32dbg`,
`httpdebuggerui`, `ida`, `ida64`, `scylla`, `processhacker`.

## Running the tests

```bat
pytest -v test_anticheat.py
```

All checks are dependency-free (Python stdlib only).
