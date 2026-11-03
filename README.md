# Javelin Anti-Cheat (`py-workedtask`)

Minimal Anti-Cheat guard implementations in **C++** (`AntiCheat.cpp`) and **Python** (`anti_cheat.py`) designed to prevent debugging, tampering, and execution alongside known cheat tools.

---

## Features

- **Debugger Detection**:
  - **C++**: Inspects Win32 `IsDebuggerPresent()` and low-level PEB `BeingDebugged` flag (`fs:[0x30]` / `gs:[0x60]`). On POSIX, checks `/proc/self/status` for `TracerPid`.
  - **Python**: Detects active debugger hooks via `sys.gettrace()` and native Windows `kernel32.IsDebuggerPresent()`.
- **Suspicious Process Scanning**:
  - Scans active system processes against known cheat engines, debuggers, and memory inspection utilities:
    `cheatengine.exe`, `ollydbg.exe`, `x64dbg.exe`, `httpdebuggerui.exe`, `ida.exe`, `ida64.exe`, `scylla.exe`, `processhacker.exe`.
- **Tampering & Self-Integrity Verification**:
  - **Python**: Computes streaming SHA-256 digest of the running script and validates it against `JAVELIN_EXPECTED_SHA256`.
  - **C++**: Computes runtime SHA-256 (or CRC32) of the running binary and compares it against build-time constant macros (`JAVELIN_EXPECTED_SHA256` / `JAVELIN_EXPECTED_CRC32`).

---

## Guarded Exit Codes

When any guard triggers, the application executes a guarded exit with diagnostic stderr output and the following status codes:

| Code (Hex) | Code (Dec) | Constant | Meaning |
| :--- | :--- | :--- | :--- |
| `0x0` | `0` | `EXIT_OK` | All checks passed cleanly. |
| `0xDEB` | `3563` | `EXIT_DEBUGGER_DETECTED` | Debugger or tracing hook detected. |
| `0xBAD` | `2989` | `EXIT_SUSPICIOUS_PROCESS` | Prohibited tool or cheat engine running. |
| `0x54A` | `1354` | `EXIT_INTEGRITY_FAILURE` | File digest mismatch or binary tampering detected. |

---

## Python Guide (`anti_cheat.py`)

### 1. Compute Script SHA-256

Use the built-in `--hash-file` CLI helper, standard OS tools, or Python:

```bash
# Using the built-in CLI helper:
python anti_cheat.py --hash-file anti_cheat.py

# Windows PowerShell:
(Get-FileHash -Algorithm SHA256 .\anti_cheat.py).Hash.ToLower()

# Windows Command Prompt:
certutil -hashfile anti_cheat.py SHA256

# Linux / macOS:
sha256sum anti_cheat.py
```

### 2. Set Expected Environment Variable

Integrity verification is **opt-in**. If `JAVELIN_EXPECTED_SHA256` is unset or empty, the integrity check is skipped for development convenience.

#### Windows PowerShell
```powershell
$env:JAVELIN_EXPECTED_SHA256 = "<computed_sha256_hex>"
python anti_cheat.py
```

#### Windows CMD
```cmd
set JAVELIN_EXPECTED_SHA256=<computed_sha256_hex>
python anti_cheat.py
```

#### Linux / macOS (Bash / Zsh)
```bash
export JAVELIN_EXPECTED_SHA256="<computed_sha256_hex>"
python3 anti_cheat.py
```

### 3. Verify Guarded Exit on Tampering

If the script is modified or if `JAVELIN_EXPECTED_SHA256` contains an unexpected hash, the process immediately aborts:

```text
[Javelin AntiCheat] starting checks...
[Javelin AntiCheat] Integrity check failed (SHA-256 mismatch). Exiting.
Exit code: 1354 (0x54A)
```

---

## C++ Guide (`AntiCheat.cpp`)

The C++ client supports compile-time verification using either SHA-256 (recommended, FIPS 180-2 self-contained implementation) or CRC32.

### 1. Build Baseline Binary

```bash
# MSVC Developer Command Prompt:
cl.exe /nologo /EHsc AntiCheat.cpp /Fe:AntiCheat.exe

# MinGW / GCC:
g++ -O2 AntiCheat.cpp -o AntiCheat.exe
```

### 2. Compute Binary Hash

```powershell
# PowerShell:
(Get-FileHash -Algorithm SHA256 .\AntiCheat.exe).Hash.ToLower()

# Linux / MinGW:
sha256sum AntiCheat.exe
```

### 3. Compile with Build-Time Constant

Pass the expected digest via compiler macro definition:

#### SHA-256 Macro (`JAVELIN_EXPECTED_SHA256`):
```bash
# MSVC:
cl.exe /nologo /EHsc /DJAVELIN_EXPECTED_SHA256="\"<expected_sha256_hex>\"" AntiCheat.cpp /Fe:AntiCheat.exe

# GCC / Clang:
g++ -O2 -DJAVELIN_EXPECTED_SHA256=\"<expected_sha256_hex>\" AntiCheat.cpp -o AntiCheat.exe
```

#### CRC32 Macro (`JAVELIN_EXPECTED_CRC32`):
```bash
# MSVC:
cl.exe /nologo /EHsc /DJAVELIN_EXPECTED_CRC32=0x12345678 AntiCheat.cpp /Fe:AntiCheat.exe

# GCC / Clang:
g++ -O2 -DJAVELIN_EXPECTED_CRC32=0x12345678 AntiCheat.cpp -o AntiCheat.exe
```

If neither macro is supplied, integrity verification is skipped.

---

## Automated Tests

Run the unit test suite using `unittest`:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

Or using `pytest`:

```bash
pytest tests/ -v
```

---

## Continuous Integration (CI)

A GitHub Actions workflow (`.github/workflows/ci.yml`) runs tests on both **Windows** and **Ubuntu** runners:
- Python 3.10, 3.11, 3.12 unit test suite.
- C++ build verification (MSVC and GCC) including matching and mismatch integrity validation.
