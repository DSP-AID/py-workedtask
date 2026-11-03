// AntiCheat.cpp
// Javelin Project - Minimal Anti-Cheat guards
// Features: debugger detection, suspicious process scan, self-integrity (CRC32 & SHA-256)

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#include <intrin.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <cstring>
#endif

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstdint>

static const char* kTag = "[Javelin AntiCheat] ";

// --- Guarded Exit Codes ---
enum ExitCode {
    EXIT_OK = 0,
    EXIT_DEBUGGER_DETECTED = 0xDEB,
    EXIT_SUSPICIOUS_PROCESS = 0xBAD,
    EXIT_INTEGRITY_FAILURE = 0x54A // Standard guarded exit code for integrity check failure (replaces invalid 0xCRC)
};

// --- Configurable lists ---
static const std::vector<std::string> kSuspiciousProcesses = {
    "cheatengine.exe",
    "ollydbg.exe",
    "x64dbg.exe",
    "httpdebuggerui.exe",
    "ida.exe",
    "ida64.exe",
    "scylla.exe",
    "processhacker.exe"
};

// --- Utils ---
static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(::tolower(c));
    });
    return s;
}

// Constant-time string comparison to prevent timing side-channel attacks
static bool constantTimeEquals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    uint8_t diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    }
    return diff == 0;
}

// Simple CRC32 (polynomial 0xEDB88320)
static uint32_t crc32(const std::vector<uint8_t>& data) {
    uint32_t crc = 0xFFFFFFFFu;
    for (uint8_t b : data) {
        crc ^= b;
        for (int i = 0; i < 8; ++i) {
            uint32_t mask = -(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

// --- FIPS 180-2 SHA-256 Self-Contained Implementation ---
class SHA256 {
private:
    uint32_t m_state[8];
    uint64_t m_count;
    uint8_t m_buffer[64];

    static inline uint32_t rotr(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }

    void transform(const uint8_t data[64]) {
        static const uint32_t K[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        uint32_t W[64];
        for (int i = 0; i < 16; ++i) {
            W[i] = (static_cast<uint32_t>(data[i * 4]) << 24) |
                   (static_cast<uint32_t>(data[i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(data[i * 4 + 2]) << 8) |
                   (static_cast<uint32_t>(data[i * 4 + 3]));
        }
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >> 3);
            uint32_t s1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >> 10);
            W[i] = W[i - 16] + s0 + W[i - 7] + s1;
        }

        uint32_t a = m_state[0];
        uint32_t b = m_state[1];
        uint32_t c = m_state[2];
        uint32_t d = m_state[3];
        uint32_t e = m_state[4];
        uint32_t f = m_state[5];
        uint32_t g = m_state[6];
        uint32_t h = m_state[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = h + S1 + ch + K[i] + W[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        m_state[0] += a;
        m_state[1] += b;
        m_state[2] += c;
        m_state[3] += d;
        m_state[4] += e;
        m_state[5] += f;
        m_state[6] += g;
        m_state[7] += h;
    }

public:
    SHA256() {
        reset();
    }

    void reset() {
        m_state[0] = 0x6a09e667;
        m_state[1] = 0xbb67ae85;
        m_state[2] = 0x3c6ef372;
        m_state[3] = 0xa54ff53a;
        m_state[4] = 0x510e527f;
        m_state[5] = 0x9b05688c;
        m_state[6] = 0x1f83d9ab;
        m_state[7] = 0x5be0cd19;
        m_count = 0;
    }

    void update(const uint8_t* data, size_t len) {
        size_t bufferIndex = static_cast<size_t>((m_count >> 3) & 0x3f);
        m_count += static_cast<uint64_t>(len) << 3;

        size_t partLen = 64 - bufferIndex;
        size_t i = 0;

        if (len >= partLen) {
            std::memcpy(&m_buffer[bufferIndex], data, partLen);
            transform(m_buffer);
            for (i = partLen; i + 63 < len; i += 64) {
                transform(&data[i]);
            }
            bufferIndex = 0;
        }
        if (i < len) {
            std::memcpy(&m_buffer[bufferIndex], &data[i], len - i);
        }
    }

    std::string finalize() {
        uint8_t finalCount[8];
        for (int i = 0; i < 8; ++i) {
            finalCount[i] = static_cast<uint8_t>((m_count >> ((7 - i) * 8)) & 0xFF);
        }

        static const uint8_t PADDING[64] = { 0x80 };
        size_t bufferIndex = static_cast<size_t>((m_count >> 3) & 0x3f);
        size_t padLen = (bufferIndex < 56) ? (56 - bufferIndex) : (120 - bufferIndex);
        update(PADDING, padLen);
        update(finalCount, 8);

        std::ostringstream ss;
        ss << std::hex << std::setfill('0');
        for (int i = 0; i < 8; ++i) {
            ss << std::setw(8) << m_state[i];
        }
        return ss.str();
    }
};

static bool readFile(const std::wstring& path, std::vector<uint8_t>& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    f.seekg(0, std::ios::end);
    std::streamsize size = f.tellg();
    if (size <= 0) return false;
    f.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(size));
    if (!f.read(reinterpret_cast<char*>(out.data()), size)) return false;
    return true;
}

static std::wstring getExecutablePath() {
#ifdef _WIN32
    std::vector<wchar_t> buffer(MAX_PATH);
    while (true) {
        DWORD len = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (len == 0) return L"";
        if (len < buffer.size() - 1 && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            return std::wstring(buffer.data(), len);
        }
        buffer.resize(buffer.size() * 2);
    }
#else
    char buffer[4096];
    ssize_t len = readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);
    if (len <= 0) return L"";
    buffer[len] = '\0';
    std::string s(buffer);
    return std::wstring(s.begin(), s.end());
#endif
}

// --- Checks ---
static bool checkDebugger() {
#ifdef _WIN32
    if (IsDebuggerPresent()) return true;

    // Secondary anti-debug: CheckBeingDebugged flag in PEB
#ifdef _M_IX86
    __try {
        BYTE* peb = *(BYTE**)__readfsdword(0x30);
        if (peb && peb[2]) return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
#elif defined(_M_X64)
    __try {
        BYTE* peb = *(BYTE**)__readgsqword(0x60);
        if (peb && peb[2]) return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
#endif
    return false;
#else
    // POSIX TracerPid check via /proc/self/status
    std::ifstream status("/proc/self/status");
    if (!status) return false;
    std::string line;
    while (std::getline(status, line)) {
        if (line.rfind("TracerPid:", 0) == 0) {
            std::istringstream iss(line.substr(10));
            int tracerPid = 0;
            if (iss >> tracerPid && tracerPid != 0) return true;
        }
    }
    return false;
#endif
}

static bool checkSuspiciousProcesses() {
#ifdef _WIN32
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);
    if (!Process32First(snap, &pe)) {
        CloseHandle(snap);
        return false;
    }

    do {
        std::string name = toLower(pe.szExeFile);
        for (const auto& bad : kSuspiciousProcesses) {
            if (name == toLower(bad)) {
                CloseHandle(snap);
                return true;
            }
        }
    } while (Process32Next(snap, &pe));

    CloseHandle(snap);
    return false;
#else
    return false;
#endif
}

// Check CRC32 integrity against expected uint32 value
static bool checkSelfIntegrityCrc32(uint32_t expectedCrc) {
    std::wstring path = getExecutablePath();
    if (path.empty()) return false;

    std::vector<uint8_t> bytes;
    if (!readFile(path, bytes)) return false;

    uint32_t current = crc32(bytes);
    return current == expectedCrc;
}

// Check SHA-256 integrity against expected hex digest string
static bool checkSelfIntegritySha256(const std::string& expectedHex) {
    std::wstring path = getExecutablePath();
    if (path.empty()) return false;

    std::ifstream f(path, std::ios::binary);
    if (!f) return false;

    SHA256 sha;
    std::vector<uint8_t> chunk(65536);
    while (f) {
        f.read(reinterpret_cast<char*>(chunk.data()), chunk.size());
        std::streamsize bytesRead = f.gcount();
        if (bytesRead > 0) {
            sha.update(chunk.data(), static_cast<size_t>(bytesRead));
        }
    }

    std::string actualHex = toLower(sha.finalize());
    std::string cleanExpected = toLower(expectedHex);
    return constantTimeEquals(actualHex, cleanExpected);
}

// Backward-compatible alias for existing callers
static bool checkSelfIntegrity(uint32_t expectedCrc) {
    return checkSelfIntegrityCrc32(expectedCrc);
}

// --- Entry helper constants ---
#ifndef JAVELIN_EXPECTED_CRC32
#define JAVELIN_EXPECTED_CRC32 0u  // Set at build time (e.g., /DJAVELIN_EXPECTED_CRC32=0x12345678)
#endif

#ifdef JAVELIN_EXPECTED_SHA256
#define JAVELIN_STRINGIFY_IMPL(x) #x
#define JAVELIN_STRINGIFY(x) JAVELIN_STRINGIFY_IMPL(x)
static std::string getExpectedSha256() {
    std::string s = JAVELIN_STRINGIFY(JAVELIN_EXPECTED_SHA256);
    if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
        s = s.substr(1, s.size() - 2);
    }
    return s;
}
#else
static std::string getExpectedSha256() {
    return "";
}
#endif

int main() {
    std::cout << kTag << "starting checks...\n";

    if (checkDebugger()) {
        std::cerr << kTag << "Debugger detected. Exiting.\n";
        return EXIT_DEBUGGER_DETECTED;
    }

    if (checkSuspiciousProcesses()) {
        std::cerr << kTag << "Suspicious process detected. Exiting.\n";
        return EXIT_SUSPICIOUS_PROCESS;
    }

    // SHA-256 build-time check (preferred cryptographic hash)
    std::string expectedSha256 = getExpectedSha256();
    if (!expectedSha256.empty()) {
        if (!checkSelfIntegritySha256(expectedSha256)) {
            std::cerr << kTag << "Integrity check failed (SHA-256 mismatch). Exiting.\n";
            return EXIT_INTEGRITY_FAILURE;
        }
    }

    // CRC32 build-time check (legacy/alternative check)
    if (JAVELIN_EXPECTED_CRC32 != 0u) {
        if (!checkSelfIntegrityCrc32(JAVELIN_EXPECTED_CRC32)) {
            std::cerr << kTag << "Integrity check failed (CRC mismatch). Exiting.\n";
            return EXIT_INTEGRITY_FAILURE;
        }
    }

    std::cout << kTag << "All clear. Continue.\n";
    return EXIT_OK;
}
