"""Command-line interface (CLI) for OPKE v2.0."""

import argparse
import ctypes
import ctypes.util
import os
import stat
import sys
import time
from typing import Optional, Union

from opke import __version__
from opke.core import (
    DEFAULT_M_KIB,
    DEFAULT_T,
    DEFAULT_P,
    PROFILES,
    SALT_LEN,
    MAX_M_KIB,
    MIN_M_KIB,
    MAX_T,
    MIN_T,
    MAX_P,
    MIN_P,
    MIN_CIPHERTEXT_BYTES,
    AuthenticationError,
    CryptoError,
    derive_key_and_split,
    encrypt_cascade,
    decrypt_cascade,
)
from opke.envelope import (
    MAX_ENVELOPE_CHARS,
    create_envelope,
    deserialize_envelope,
    serialize_envelope,
    EnvelopeValidationError,
)
from opke.qr import generate_qr_image, print_terminal_qr
from opke.security import (
    MAX_SECRET_BYTES,
    MAX_PASSPHRASE_BYTES,
    prompt_passphrase,
    prompt_secret,
    zero_memory,
    write_secure_file,
    read_secure_file,
)


def get_version_string() -> str:
    return f"OPKE (Offline Paper-Key Encryptor) v{__version__}"


def get_available_memory_kib() -> Optional[int]:
    """Retrieves available physical memory in KiB, taking into account cgroups (Docker/containers),
    Linux /proc/meminfo, POSIX sysconf, and Windows GlobalMemoryStatusEx."""
    cgroup_kib: Optional[int] = None
    # 0. Check Linux cgroups (container limits in Docker/K8s)
    if os.path.exists("/sys/fs/cgroup/memory.max"):
        try:
            with open("/sys/fs/cgroup/memory.max", "r") as f:
                val = f.read().strip()
                if val.isdigit():
                    limit_bytes = int(val)
                    curr_bytes = 0
                    if os.path.exists("/sys/fs/cgroup/memory.current"):
                        try:
                            with open("/sys/fs/cgroup/memory.current", "r") as fc:
                                c_val = fc.read().strip()
                                if c_val.isdigit():
                                    curr_bytes = int(c_val)
                        except Exception:
                            pass
                    cgroup_kib = max(0, limit_bytes - curr_bytes) // 1024
        except Exception:
            pass
    if cgroup_kib is None and os.path.exists("/sys/fs/cgroup/memory/memory.limit_in_bytes"):
        try:
            with open("/sys/fs/cgroup/memory/memory.limit_in_bytes", "r") as f:
                val = f.read().strip()
                if val.isdigit():
                    lim = int(val)
                    if lim < 1024 * 1024 * 1024 * 1024:  # Filter unbounded values
                        curr = 0
                        if os.path.exists("/sys/fs/cgroup/memory/memory.usage_in_bytes"):
                            try:
                                with open("/sys/fs/cgroup/memory/memory.usage_in_bytes", "r") as fu:
                                    u_val = fu.read().strip()
                                    if u_val.isdigit():
                                        curr = int(u_val)
                            except Exception:
                                pass
                        cgroup_kib = max(0, lim - curr) // 1024
        except Exception:
            pass

    avail: Optional[int] = None

    # 1. Linux /proc/meminfo
    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    avail = int(line.split()[1])
                    break
    except Exception:
        pass

    # 2. POSIX sysconf (macOS, BSD, fallback Linux)
    if avail is None:
        try:
            pages = os.sysconf("SC_AVPHYS_PAGES")
            page_size = os.sysconf("SC_PAGESIZE")
            avail = (pages * page_size) // 1024
        except Exception:
            pass

    # 3. Windows GlobalMemoryStatusEx via ctypes
    if avail is None and sys.platform == "win32":
        try:
            import ctypes

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                avail = stat.ullAvailPhys // 1024
        except Exception:
            pass

    if cgroup_kib is not None:
        if avail is not None:
            return min(avail, cgroup_kib)
        return cgroup_kib

    return avail


def _wipe_native_memory(targets: list) -> None:
    """Overwrites sensitive strings in Linux native cmdline and environ memory to prevent /proc leakage."""
    if not sys.platform.startswith("linux") or not targets:
        return
    try:
        if not os.path.exists("/proc/self/stat"):
            return
        with open("/proc/self/stat", "r") as f:
            content = f.read()
        idx = content.rfind(")")
        if idx == -1:
            return
        fields = content[idx + 2:].split()
        if len(fields) <= 48:
            return
        arg_start = int(fields[45])
        arg_end = int(fields[46])
        env_start = int(fields[47])
        env_end = int(fields[48])

        # Wipe targets from cmdline and environ regions
        for start, end in [(arg_start, arg_end), (env_start, env_end)]:
            if end > start:
                length = end - start
                buf = (ctypes.c_char * length).from_address(start)
                raw = bytes(buf)
                for t in targets:
                    if not t:
                        continue
                    b_t = t if isinstance(t, (bytes, bytearray)) else t.encode("utf-8")
                    pos = 0
                    while True:
                        pos = raw.find(b_t, pos)
                        if pos == -1:
                            break
                        ctypes.memset(start + pos, ord("X"), len(b_t))
                        pos += len(b_t)
    except Exception:
        pass


def scrub_env_passphrase() -> Optional[bytearray]:
    """Retrieves and scrubs OPKE_PASSPHRASE from os.environ, libc, and Linux native environ memory."""
    if "OPKE_PASSPHRASE" not in os.environ:
        return None
    val = os.environ.pop("OPKE_PASSPHRASE")
    if not val:
        raise ValueError("Passphrase cannot be empty (OPKE_PASSPHRASE environment variable is empty).")

    # Scrub from libc unsetenv if available
    try:
        import ctypes.util
        libc_path = ctypes.util.find_library("c")
        if libc_path:
            libc = ctypes.CDLL(libc_path)
            if hasattr(libc, "unsetenv"):
                libc.unsetenv(b"OPKE_PASSPHRASE")
    except Exception:
        pass

    # Scrub from Linux native environ memory
    try:
        _wipe_native_memory([f"OPKE_PASSPHRASE={val}".encode("utf-8"), val.encode("utf-8")])
    except Exception:
        pass

    raw_bytes = val.encode("utf-8")
    if len(raw_bytes) > MAX_PASSPHRASE_BYTES:
        raise ValueError(f"Passphrase exceeds maximum allowed length ({MAX_PASSPHRASE_BYTES} bytes).")
    res = bytearray(raw_bytes)
    del val
    return res


def redact_argv(args: Optional[argparse.Namespace] = None) -> None:
    """Redacts passwords and secrets from sys.argv in-place and masks process name to protect process table inspection."""
    native_targets = []
    try:
        if sys.platform.startswith("linux"):
            import ctypes
            import ctypes.util
            libc_path = ctypes.util.find_library("c")
            if libc_path:
                libc = ctypes.CDLL(libc_path)
                if hasattr(libc, "prctl"):
                    libc.prctl(15, b"opke\x00", 0, 0, 0)
    except Exception:
        pass

    valued_options = {
        "-p", "--passphrase",
        "-i", "--input-file",
        "-o", "--output",
        "--profile",
        "--mem", "--time", "--threads",
        "--qr", "--max-mem",
    }

    # 1. Redact based on parsed args if available
    if args is not None:
        raw_secret = getattr(args, "secret", None)
        if isinstance(raw_secret, str) and raw_secret:
            native_targets.append(raw_secret.encode("utf-8"))
            for i in range(1, len(sys.argv)):
                if sys.argv[i] == raw_secret:
                    sys.argv[i] = "[REDACTED]"
        raw_passphrase = getattr(args, "passphrase", None)
        if isinstance(raw_passphrase, str) and raw_passphrase:
            native_targets.append(raw_passphrase.encode("utf-8"))
            for i in range(1, len(sys.argv)):
                if sys.argv[i] == raw_passphrase:
                    sys.argv[i] = "[REDACTED]"
                elif sys.argv[i].startswith("-p="):
                    sys.argv[i] = "-p=[REDACTED]"
                elif sys.argv[i].startswith("--passphrase="):
                    sys.argv[i] = "--passphrase=[REDACTED]"
                elif sys.argv[i].startswith("-p") and not sys.argv[i].startswith("--"):
                    sys.argv[i] = "-p[REDACTED]"

    # 2. Structural scan of sys.argv
    skip_next = False
    is_encrypt = len(sys.argv) > 1 and sys.argv[1] == "encrypt"
    seen_encrypt_secret = False

    for i in range(1, len(sys.argv)):
        arg = sys.argv[i]
        prev = sys.argv[i - 1]

        if skip_next:
            skip_next = False
            if prev in ("-p", "--passphrase"):
                native_targets.append(arg.encode("utf-8"))
                sys.argv[i] = "[REDACTED]"
            continue

        if arg.startswith("-p=") or arg.startswith("--passphrase="):
            prefix = "-p=" if arg.startswith("-p=") else "--passphrase="
            native_targets.append(arg[len(prefix):].encode("utf-8"))
            sys.argv[i] = f"{prefix}[REDACTED]"
            continue

        if arg.startswith("-p") and len(arg) > 2 and not arg.startswith("--"):
            native_targets.append(arg[2:].encode("utf-8"))
            sys.argv[i] = "-p[REDACTED]"
            continue

        if arg in ("-p", "--passphrase"):
            skip_next = True
            continue

        if arg in valued_options:
            skip_next = True
            continue

        if is_encrypt and not seen_encrypt_secret and i >= 2 and not arg.startswith("-"):
            native_targets.append(arg.encode("utf-8"))
            sys.argv[i] = "[REDACTED]"
            seen_encrypt_secret = True

    # Overwrite in Linux native memory
    if native_targets:
        _wipe_native_memory(native_targets)


def cmd_encrypt(args: argparse.Namespace) -> int:
    """Handles the 'encrypt' command."""
    secret_bytes: Optional[bytearray] = None
    passphrase_bytes: Optional[bytearray] = None
    key_chacha: Optional[bytearray] = None
    key_aes: Optional[bytearray] = None

    try:
        # 1. Resolve and validate KDF parameters first
        profile = PROFILES.get(args.profile.lower(), PROFILES["production"])
        m_kib = args.mem if args.mem is not None else profile["m_kib"]
        t = args.time if args.time is not None else profile["t"]
        p = args.threads if args.threads is not None else profile["p"]

        # Validate KDF parameter bounds
        if m_kib < MIN_M_KIB:
            print(f"[-] Invalid memory cost: {m_kib} KiB (must be at least {MIN_M_KIB} KiB)", file=sys.stderr)
            return 1
        if m_kib > MAX_M_KIB:
            print(f"[-] Invalid memory cost: {m_kib} KiB (exceeds maximum allowed {MAX_M_KIB} KiB)", file=sys.stderr)
            return 1
        if p < MIN_P or p > MAX_P:
            print(f"[-] Invalid parallelism: {p} (must be between {MIN_P} and {MAX_P})", file=sys.stderr)
            return 1
        if m_kib < 8 * p:
            print(f"[-] Invalid memory cost: {m_kib} KiB (Argon2 requires m >= 8 * p = {8 * p} KiB)", file=sys.stderr)
            return 1
        if t < MIN_T or t > MAX_T:
            print(f"[-] Invalid time cost: {t} (must be between {MIN_T} and {MAX_T})", file=sys.stderr)
            return 1

        # Check memory availability to prevent OOM freezes
        avail_kib = get_available_memory_kib()
        if avail_kib is not None and m_kib > avail_kib and not getattr(args, "force", False):
            print(
                f"[-] Selected parameters require {m_kib:,} KiB ({m_kib / 1024 / 1024:.2f} GiB) RAM, "
                f"but only ~{avail_kib:,} KiB ({avail_kib / 1024 / 1024:.2f} GiB) is available.",
                file=sys.stderr,
            )
            print("[-] Encryption aborted to prevent system freeze / OOM. Use '--profile moderate' or '--force' to override.", file=sys.stderr)
            return 1

        # Pre-check destination paths before prompting user for credentials
        if args.output:
            if os.path.lexists(args.output):
                st_out = os.lstat(args.output)
                if stat.S_ISLNK(st_out.st_mode):
                    print(f"[-] Refusing to write to symlink for security: {args.output}", file=sys.stderr)
                    return 1
                if not stat.S_ISREG(st_out.st_mode):
                    print(f"[-] Refusing to write to non-regular file for security: {args.output}", file=sys.stderr)
                    return 1
                if st_out.st_nlink > 1:
                    print(f"[-] Refusing to write to hardlink target for security: {args.output}", file=sys.stderr)
                    return 1

        if args.qr:
            if not (args.qr.lower().endswith(".png") or args.qr.lower().endswith(".svg")):
                print(f"[-] QR code output format unsupported: '{args.qr}'. Target file must have a .png or .svg extension.", file=sys.stderr)
                return 1
            if os.path.lexists(args.qr):
                st_qr = os.lstat(args.qr)
                if stat.S_ISLNK(st_qr.st_mode):
                    print(f"[-] Refusing to write to symlink for security: {args.qr}", file=sys.stderr)
                    return 1
                if not stat.S_ISREG(st_qr.st_mode):
                    print(f"[-] Refusing to write to non-regular file for security: {args.qr}", file=sys.stderr)
                    return 1
                if st_qr.st_nlink > 1:
                    print(f"[-] Refusing to write to hardlink target for security: {args.qr}", file=sys.stderr)
                    return 1

        # 2. Resolve secret plaintext
        if args.secret:
            print(
                "[!] SECURITY WARNING: Passing secret as command-line argument exposes it to "
                "process tables (ps aux), /proc, and shell history!",
                file=sys.stderr,
            )
            raw_secret_bytes = args.secret.encode("utf-8")
            if len(raw_secret_bytes) > MAX_SECRET_BYTES:
                print(f"[-] Secret exceeds maximum allowed size ({MAX_SECRET_BYTES} bytes).", file=sys.stderr)
                return 1
            secret_bytes = bytearray(raw_secret_bytes)
            args.secret = None
        elif args.input_file:
            try:
                secret_bytes = read_secure_file(args.input_file, is_binary=True, max_bytes=MAX_SECRET_BYTES)
            except Exception as e:
                print(f"[-] Error reading input file: {e}", file=sys.stderr)
                return 1
        elif not sys.stdin.isatty():
            secret_bytes = prompt_secret(multiline=True)
        else:
            print("[*] Interactive secret entry (input will be hidden):", file=sys.stderr)
            secret_bytes = prompt_secret(multiline=args.multiline)

        if not secret_bytes:
            print("[-] Secret cannot be empty.", file=sys.stderr)
            return 1

        # 3. Resolve passphrase
        if args.passphrase is not None:
            if not args.passphrase:
                print("[-] Passphrase cannot be empty.", file=sys.stderr)
                return 1
            print(
                "[!] SECURITY WARNING: Passing passphrase as command-line argument exposes it to "
                "process tables (ps aux), /proc, and shell history!",
                file=sys.stderr,
            )
            raw_pass_bytes = args.passphrase.encode("utf-8")
            if len(raw_pass_bytes) > MAX_PASSPHRASE_BYTES:
                print(f"[-] Passphrase exceeds maximum allowed length ({MAX_PASSPHRASE_BYTES} bytes).", file=sys.stderr)
                return 1
            passphrase_bytes = bytearray(raw_pass_bytes)
            args.passphrase = None
        else:
            try:
                passphrase_bytes = scrub_env_passphrase()
            except ValueError as e:
                print(f"[-] {e}", file=sys.stderr)
                return 1
            if passphrase_bytes is None:
                passphrase_bytes = prompt_passphrase(confirm=True)

        if not passphrase_bytes or len(passphrase_bytes) == 0:
            print("[-] Passphrase cannot be empty.", file=sys.stderr)
            return 1

        print(
            f"[*] Deriving keys with Argon2id (m={m_kib} KiB ({m_kib / 1024 / 1024:.2f} GiB), t={t}, p={p})...",
            file=sys.stderr,
        )
        t0 = time.time()
        salt = os.urandom(SALT_LEN)
        key_chacha, key_aes = derive_key_and_split(
            passphrase=passphrase_bytes,
            salt=salt,
            m_kib=m_kib,
            t=t,
            p=p,
        )
        zero_memory(passphrase_bytes)
        passphrase_bytes = None

        kdf_elapsed = time.time() - t0
        print(f"[*] Key derivation completed in {kdf_elapsed:.2f}s.", file=sys.stderr)

        # 4. Perform Cascade AEAD Encryption
        final_ciphertext, tag_aes, nonce_chacha, nonce_aes = encrypt_cascade(
            plaintext=secret_bytes,
            key_chacha=key_chacha,
            key_aes=key_aes,
        )
        zero_memory(secret_bytes)
        zero_memory(key_chacha)
        zero_memory(key_aes)
        secret_bytes = None
        key_chacha = None
        key_aes = None

        # 5. Build Envelope
        envelope = create_envelope(
            salt=salt,
            m_kib=m_kib,
            t=t,
            p=p,
            nonce_chacha=nonce_chacha,
            nonce_aes=nonce_aes,
            tag_aes=tag_aes,
            final_ciphertext=final_ciphertext,
        )

        paper_output = envelope.to_paper_format()
        raw_b64 = envelope.to_base64_payload()

        # 6. Save or Output Envelope
        if args.output:
            try:
                write_secure_file(args.output, raw_b64 + "\n" if args.raw else paper_output, is_binary=False)
                print(f"[+] Encrypted envelope written to: {args.output}", file=sys.stderr)
            except Exception as e:
                print(f"[-] Failed to write envelope to {args.output}: {e}", file=sys.stderr)
                return 1
        else:
            if args.raw:
                print(raw_b64)
            else:
                print(paper_output)

        # 7. QR Code generation if requested
        if args.qr:
            try:
                generate_qr_image(raw_b64, args.qr)
                print(f"[+] QR Code image saved to: {args.qr}", file=sys.stderr)
            except Exception as e:
                print(f"[-] Failed to generate QR Code image: {e}", file=sys.stderr)
                return 1

        if args.qr_term:
            print("\n[*] Scan QR code directly from terminal:", file=sys.stderr)
            print_terminal_qr(raw_b64)

        return 0

    except Exception as e:
        print(f"[-] Error during encryption: {e}", file=sys.stderr)
        return 1
    finally:
        zero_memory(secret_bytes)
        zero_memory(passphrase_bytes)
        zero_memory(key_chacha)
        zero_memory(key_aes)
        if hasattr(args, "secret"):
            args.secret = None
        if hasattr(args, "passphrase"):
            args.passphrase = None
        del secret_bytes, passphrase_bytes, key_chacha, key_aes


def cmd_decrypt(args: argparse.Namespace) -> int:
    """Handles the 'decrypt' command."""
    passphrase_bytes: Optional[bytearray] = None
    key_chacha: Optional[bytearray] = None
    key_aes: Optional[bytearray] = None
    plaintext: Optional[bytearray] = None

    try:
        # Validate limit options upfront
        if getattr(args, "max_mem", None) is not None:
            if args.max_mem < MIN_M_KIB:
                print(f"[-] Invalid --max-mem: {args.max_mem} KiB (must be at least {MIN_M_KIB} KiB)", file=sys.stderr)
                return 1

        if getattr(args, "max_time", None) is not None:
            if args.max_time < MIN_T:
                print(f"[-] Invalid --max-time: {args.max_time} (must be at least {MIN_T})", file=sys.stderr)
                return 1

        if getattr(args, "max_threads", None) is not None:
            if args.max_threads < MIN_P:
                print(f"[-] Invalid --max-threads: {args.max_threads} (must be at least {MIN_P})", file=sys.stderr)
                return 1

        # 1. Read input envelope
        raw_input: Optional[str] = None
        if args.input:
            raw_input = args.input
        elif args.input_file:
            try:
                raw_input = read_secure_file(args.input_file, is_binary=False, max_bytes=MAX_ENVELOPE_CHARS)
            except Exception as e:
                print(f"[-] Error reading envelope file: {e}", file=sys.stderr)
                return 1
        elif not sys.stdin.isatty():
            raw_input = sys.stdin.read(MAX_ENVELOPE_CHARS + 1)
            if len(raw_input) > MAX_ENVELOPE_CHARS:
                print(f"[-] Envelope input exceeds maximum allowed size ({MAX_ENVELOPE_CHARS} chars).", file=sys.stderr)
                return 1
        else:
            print("[*] Paste your OPKE envelope (or PEM block), then press Ctrl+D:", file=sys.stderr)
            raw_input = sys.stdin.read(MAX_ENVELOPE_CHARS + 1)
            if len(raw_input) > MAX_ENVELOPE_CHARS:
                print(f"[-] Envelope input exceeds maximum allowed size ({MAX_ENVELOPE_CHARS} chars).", file=sys.stderr)
                return 1

        if not raw_input or not raw_input.strip():
            print("[-] Envelope input is empty.", file=sys.stderr)
            return 1

        # 2. Parse and validate envelope
        try:
            envelope = deserialize_envelope(raw_input)
        except EnvelopeValidationError as e:
            print(f"[-] Invalid OPKE envelope: {e}", file=sys.stderr)
            return 1

        # 3. Check memory and execution constraints BEFORE prompting user for passphrase
        m_kib = envelope.kdf.m_kib
        t = envelope.kdf.t
        p = envelope.kdf.p

        if args.max_mem is not None and m_kib > args.max_mem:
            print(
                f"[-] Envelope memory requirement ({m_kib:,} KiB) exceeds specified --max-mem limit ({args.max_mem:,} KiB).",
                file=sys.stderr,
            )
            return 1

        if getattr(args, "max_time", None) is not None and t > args.max_time:
            print(
                f"[-] Envelope time requirement ({t} iterations) exceeds specified --max-time limit ({args.max_time}).",
                file=sys.stderr,
            )
            return 1

        if getattr(args, "max_threads", None) is not None and p > args.max_threads:
            print(
                f"[-] Envelope parallelism requirement ({p} threads) exceeds specified --max-threads limit ({args.max_threads}).",
                file=sys.stderr,
            )
            return 1

        avail_kib = get_available_memory_kib()
        if avail_kib is not None and m_kib > avail_kib and not args.force:
            print(
                f"[-] Envelope requires {m_kib:,} KiB ({m_kib / 1024 / 1024:.2f} GiB) RAM, "
                f"but only ~{avail_kib:,} KiB ({avail_kib / 1024 / 1024:.2f} GiB) is available.",
                file=sys.stderr,
            )
            print("[-] Decryption aborted to prevent system freeze / OOM. Use --force to override.", file=sys.stderr)
            return 1
        elif avail_kib is None and m_kib > DEFAULT_M_KIB and not args.force:
            print(
                f"[-] Available system memory cannot be determined and envelope requires {m_kib:,} KiB "
                f"({m_kib / 1024 / 1024:.2f} GiB) RAM, which exceeds default safe limit ({DEFAULT_M_KIB / 1024 / 1024:.2f} GiB).",
                file=sys.stderr,
            )
            print("[-] Decryption aborted to prevent system freeze / OOM. Use --force to override.", file=sys.stderr)
            return 1

        # Pre-check destination path before prompting user for credentials
        if args.output:
            if os.path.lexists(args.output):
                st_out = os.lstat(args.output)
                if stat.S_ISLNK(st_out.st_mode):
                    print(f"[-] Refusing to write to symlink for security: {args.output}", file=sys.stderr)
                    return 1
                if not stat.S_ISREG(st_out.st_mode):
                    print(f"[-] Refusing to write to non-regular file for security: {args.output}", file=sys.stderr)
                    return 1
                if st_out.st_nlink > 1:
                    print(f"[-] Refusing to write to hardlink target for security: {args.output}", file=sys.stderr)
                    return 1

        # 4. Read Passphrase (prompting only after envelope and memory safety checks pass)
        try:
            if args.passphrase is not None:
                if not args.passphrase:
                    print("[-] Passphrase cannot be empty.", file=sys.stderr)
                    return 1
                print(
                    "[!] SECURITY WARNING: Passing passphrase as command-line argument exposes it to "
                    "process tables (ps aux), /proc, and shell history!",
                    file=sys.stderr,
                )
                raw_pass_bytes = args.passphrase.encode("utf-8")
                if len(raw_pass_bytes) > MAX_PASSPHRASE_BYTES:
                    print(f"[-] Passphrase exceeds maximum allowed length ({MAX_PASSPHRASE_BYTES} bytes).", file=sys.stderr)
                    return 1
                passphrase_bytes = bytearray(raw_pass_bytes)
                args.passphrase = None
            else:
                try:
                    passphrase_bytes = scrub_env_passphrase()
                except ValueError as e:
                    print(f"[-] {e}", file=sys.stderr)
                    return 1
                if passphrase_bytes is None:
                    passphrase_bytes = prompt_passphrase(confirm=False)
        except Exception as e:
            print(f"[-] Error getting passphrase: {e}", file=sys.stderr)
            return 1

        if not passphrase_bytes or len(passphrase_bytes) == 0:
            print("[-] Passphrase cannot be empty.", file=sys.stderr)
            return 1

        salt, nonce_chacha, nonce_aes, tag_aes, final_ciphertext = envelope.get_decoded_bytes()

        print(
            f"[*] Deriving keys with Argon2id (m={m_kib} KiB ({m_kib / 1024 / 1024:.2f} GiB), t={t}, p={p})...",
            file=sys.stderr,
        )
        t0 = time.time()
        key_chacha, key_aes = derive_key_and_split(
            passphrase=passphrase_bytes,
            salt=salt,
            m_kib=m_kib,
            t=t,
            p=p,
        )
        zero_memory(passphrase_bytes)
        passphrase_bytes = None

        kdf_elapsed = time.time() - t0
        print(f"[*] Key derivation completed in {kdf_elapsed:.2f}s.", file=sys.stderr)

        # 5. Decrypt and Authenticate Cascade
        try:
            plaintext = decrypt_cascade(
                final_ciphertext=final_ciphertext,
                tag_aes=tag_aes,
                nonce_aes=nonce_aes,
                nonce_chacha=nonce_chacha,
                key_chacha=key_chacha,
                key_aes=key_aes,
            )
        except AuthenticationError as e:
            print(f"[-] {e}", file=sys.stderr)
            return 1
        except (CryptoError, ValueError, TypeError) as e:
            print(f"[-] Cryptographic error: {e}", file=sys.stderr)
            return 1
        finally:
            zero_memory(key_chacha)
            zero_memory(key_aes)
            key_chacha = None
            key_aes = None

        # 6. Output plaintext with zero_memory cleanup
        if args.output:
            try:
                write_secure_file(args.output, plaintext, is_binary=True)
                print(f"[+] Decrypted plaintext written to: {args.output}", file=sys.stderr)
            except Exception as e:
                print(f"[-] Failed to write plaintext to {args.output}: {e}", file=sys.stderr)
                return 1
        else:
            # Output raw bytes directly to buffer without mutating or adding newlines
            try:
                sys.stdout.buffer.write(plaintext)
                sys.stdout.buffer.flush()
            except BrokenPipeError:
                try:
                    sys.stdout.close()
                except Exception:
                    pass
                return 0

        return 0

    finally:
        zero_memory(passphrase_bytes)
        zero_memory(key_chacha)
        zero_memory(key_aes)
        zero_memory(plaintext)
        if hasattr(args, "passphrase"):
            args.passphrase = None
        del passphrase_bytes, key_chacha, key_aes, plaintext


def cmd_inspect(args: argparse.Namespace) -> int:
    """Handles the 'inspect' command (displays envelope metadata)."""
    raw_input: Optional[str] = None
    if args.input:
        raw_input = args.input
    elif args.input_file:
        try:
            raw_input = read_secure_file(args.input_file, is_binary=False, max_bytes=MAX_ENVELOPE_CHARS)
        except Exception as e:
            print(f"[-] Error reading envelope file: {e}", file=sys.stderr)
            return 1
    elif not sys.stdin.isatty():
        raw_input = sys.stdin.read(MAX_ENVELOPE_CHARS + 1)
        if len(raw_input) > MAX_ENVELOPE_CHARS:
            print(f"[-] Envelope input exceeds maximum allowed size ({MAX_ENVELOPE_CHARS} chars).", file=sys.stderr)
            return 1
    else:
        print("[-] Please provide an envelope via argument, --input-file, or stdin.", file=sys.stderr)
        return 1

    try:
        envelope = deserialize_envelope(raw_input)
        salt, nonce_chacha, nonce_aes, tag_aes, data = envelope.get_decoded_bytes()
    except EnvelopeValidationError as e:
        print(f"[-] Invalid envelope: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"[-] Failed to inspect envelope: {e}", file=sys.stderr)
        return 1

    m_gib = envelope.kdf.m_kib / 1024 / 1024

    print("=== OPKE Envelope Metadata ===")
    print(f"Version:         {envelope.v}")
    print("KDF:")
    print(f"  Algorithm:     {envelope.kdf.name}")
    print(f"  Memory Cost:   {envelope.kdf.m_kib:,} KiB ({m_gib:.2f} GiB)")
    print(f"  Time Cost:     {envelope.kdf.t} iterations")
    print(f"  Parallelism:   {envelope.kdf.p} threads")
    print(f"  Salt (Base64): {envelope.kdf.salt} ({len(salt)} bytes)")
    print("Cipher:")
    print(f"  Layers:        {' -> '.join(envelope.cipher.layers)}")
    print(f"  Nonce ChaCha:  {envelope.cipher.nonce_chacha} ({len(nonce_chacha)} bytes)")
    print(f"  Nonce AES:     {envelope.cipher.nonce_aes} ({len(nonce_aes)} bytes)")
    print(f"  Tag AES:       {envelope.cipher.tag_aes} ({len(tag_aes)} bytes)")
    print("Data:")
    print(f"  Ciphertext:    {len(data)} bytes")
    print("==============================")
    return 0


def cmd_benchmark(args: argparse.Namespace) -> int:
    """Measures Argon2id execution speed with specified parameters."""
    profile = PROFILES.get(args.profile.lower(), PROFILES["production"])
    m_kib = args.mem if args.mem is not None else profile["m_kib"]
    t = args.time if args.time is not None else profile["t"]
    p = args.threads if args.threads is not None else profile["p"]

    # Validate parameters
    if m_kib < MIN_M_KIB:
        print(f"[-] Invalid memory cost: {m_kib} KiB (must be at least {MIN_M_KIB} KiB)", file=sys.stderr)
        return 1
    if m_kib > MAX_M_KIB:
        print(f"[-] Invalid memory cost: {m_kib} KiB (exceeds maximum allowed {MAX_M_KIB} KiB)", file=sys.stderr)
        return 1
    if p < MIN_P or p > MAX_P:
        print(f"[-] Invalid parallelism: {p} (must be between {MIN_P} and {MAX_P})", file=sys.stderr)
        return 1
    if m_kib < 8 * p:
        print(f"[-] Invalid memory cost: {m_kib} KiB (Argon2 requires m >= 8 * p = {8 * p} KiB)", file=sys.stderr)
        return 1
    if t < MIN_T or t > MAX_T:
        print(f"[-] Invalid time cost: {t} (must be between {MIN_T} and {MAX_T})", file=sys.stderr)
        return 1

    # Check available memory
    m_gib = m_kib / 1024 / 1024
    avail_kib = get_available_memory_kib()
    if avail_kib is not None and m_kib > avail_kib and not getattr(args, "force", False):
        print(
            f"[-] Benchmark requires {m_kib:,} KiB ({m_gib:.2f} GiB) RAM, "
            f"but only ~{avail_kib:,} KiB ({avail_kib / 1024 / 1024:.2f} GiB) is available.",
            file=sys.stderr,
        )
        print("[-] Benchmark aborted to prevent system freeze / OOM. Use --force to override.", file=sys.stderr)
        return 1

    salt = os.urandom(SALT_LEN)
    dummy_passphrase = bytearray(b"OPKE_Benchmark_Passphrase_1234567890")
    k1 = None
    k2 = None

    print(f"[*] Starting Argon2id Benchmark...")
    print(f"[*] Parameters: m={m_kib:,} KiB ({m_gib:.2f} GiB), t={t}, p={p}")
    print(f"[*] Allocating and running KDF, please wait...")

    t0 = time.time()
    try:
        k1, k2 = derive_key_and_split(dummy_passphrase, salt, m_kib=m_kib, t=t, p=p)
        elapsed = time.time() - t0
    except (CryptoError, ValueError) as e:
        print(f"[-] Benchmark failed: {e}", file=sys.stderr)
        return 1
    finally:
        zero_memory(dummy_passphrase)
        zero_memory(k1)
        zero_memory(k2)
        del dummy_passphrase, k1, k2

    print(f"[+] Completed in {elapsed:.3f} seconds!")
    bandwidth = (m_gib * t) / max(elapsed, 1e-6)
    print(f"[+] Memory bandwidth evaluated: {bandwidth:.2f} GiB-iterations/sec")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="opke",
        description="Offline Paper-Key Encryptor (OPKE) v2.0 - High-security cold storage key encryption",
    )
    parser.add_argument("-v", "--version", action="version", version=get_version_string())

    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # 1. encrypt
    p_enc = subparsers.add_parser("encrypt", help="Encrypt plaintext into OPKE paper envelope")
    p_enc.add_argument("secret", nargs="?", help="Plaintext secret (optional; if omitted, prompts or reads stdin)")
    p_enc.add_argument("-i", "--input-file", help="Read plaintext from file")
    p_enc.add_argument("-m", "--multiline", action="store_true", help="Enable multi-line secret entry in interactive prompt")
    p_enc.add_argument("-p", "--passphrase", help="Passphrase (optional; prompts securely if omitted)")
    p_enc.add_argument("-o", "--output", help="Write envelope output to file")
    p_enc.add_argument(
        "--profile",
        choices=list(PROFILES.keys()),
        default="production",
        help="KDF profile (default: production = 8 GiB, 64 iters, 8 threads)",
    )
    p_enc.add_argument("--mem", type=int, help="Override KDF memory cost in KiB")
    p_enc.add_argument("--time", type=int, help="Override KDF time cost (iterations)")
    p_enc.add_argument("--threads", type=int, help="Override KDF parallelism (threads)")
    p_enc.add_argument("--force", action="store_true", help="Force execution even if memory requirements exceed available RAM")
    p_enc.add_argument("--raw", action="store_true", help="Output raw single-line Base64 instead of PEM paper format")
    p_enc.add_argument("--qr", help="Generate QR code image file (.png or .svg)")
    p_enc.add_argument("--qr-term", action="store_true", help="Print QR code directly to terminal")
    p_enc.set_defaults(func=cmd_encrypt)

    # 2. decrypt
    p_dec = subparsers.add_parser("decrypt", help="Decrypt OPKE paper envelope back to plaintext")
    p_dec.add_argument("input", nargs="?", help="OPKE envelope text (optional; if omitted, reads from file or stdin)")
    p_dec.add_argument("-i", "--input-file", help="Read envelope from file")
    p_dec.add_argument("-p", "--passphrase", help="Passphrase (optional; prompts securely if omitted)")
    p_dec.add_argument("-o", "--output", help="Write decrypted plaintext to file")
    p_dec.add_argument("--max-mem", type=int, help="Maximum allowed KDF memory cost in KiB")
    p_dec.add_argument("--max-time", type=int, help="Maximum allowed KDF time cost (iterations)")
    p_dec.add_argument("--max-threads", type=int, help="Maximum allowed KDF parallelism (threads)")
    p_dec.add_argument("--force", action="store_true", help="Force execution even if memory requirements exceed available RAM")
    p_dec.set_defaults(func=cmd_decrypt)

    # 3. inspect
    p_ins = subparsers.add_parser("inspect", help="Inspect envelope metadata without passphrase")
    p_ins.add_argument("input", nargs="?", help="OPKE envelope text")
    p_ins.add_argument("-i", "--input-file", help="Read envelope from file")
    p_ins.set_defaults(func=cmd_inspect)

    # 4. benchmark
    p_bm = subparsers.add_parser("benchmark", help="Benchmark Argon2id KDF speed on this machine")
    p_bm.add_argument(
        "--profile",
        choices=list(PROFILES.keys()),
        default="production",
        help="KDF profile to benchmark (default: production)",
    )
    p_bm.add_argument("--mem", type=int, help="Custom memory in KiB")
    p_bm.add_argument("--time", type=int, help="Custom iterations")
    p_bm.add_argument("--threads", type=int, help="Custom threads")
    p_bm.add_argument("--force", action="store_true", help="Force benchmark even if memory requirements exceed available RAM")
    p_bm.set_defaults(func=cmd_benchmark)

    return parser



def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    redact_argv(args)
    try:
        sys.exit(args.func(args))
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass
        sys.exit(0)
    except KeyboardInterrupt:
        print("\n[!] Aborted by user.", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
