"""Command-line interface (CLI) for OPKE v2.0."""

import argparse
import os
import sys
import time
from typing import Optional

from opke import __version__
from opke.core import (
    DEFAULT_M_KIB,
    DEFAULT_T,
    DEFAULT_P,
    PROFILES,
    SALT_LEN,
    AuthenticationError,
    CryptoError,
    derive_key_and_split,
    encrypt_cascade,
    decrypt_cascade,
)
from opke.envelope import (
    create_envelope,
    deserialize_envelope,
    serialize_envelope,
    EnvelopeValidationError,
)
from opke.qr import generate_qr_image, print_terminal_qr
from opke.security import prompt_passphrase, prompt_secret, zero_memory


def get_version_string() -> str:
    return f"OPKE (Offline Paper-Key Encryptor) v{__version__}"


def cmd_encrypt(args: argparse.Namespace) -> int:
    """Handles the 'encrypt' command."""
    # 1. Resolve secret plaintext
    secret_bytes: Optional[bytearray] = None
    try:
        if args.secret:
            secret_bytes = bytearray(args.secret.encode("utf-8"))
        elif args.input_file:
            with open(args.input_file, "rb") as f:
                content = f.read()
                # strip single trailing newline if present from text files
                if content.endswith(b"\r\n"):
                    content = content[:-2]
                elif content.endswith(b"\n") or content.endswith(b"\r"):
                    content = content[:-1]
                secret_bytes = bytearray(content)
        elif not sys.stdin.isatty():
            secret_bytes = prompt_secret()
        else:
            print("[*] Interactive secret entry (input will be hidden):", file=sys.stderr)
            secret_bytes = prompt_secret()
    except Exception as e:
        print(f"[-] Error reading secret: {e}", file=sys.stderr)
        return 1

    if not secret_bytes:
        print("[-] Secret cannot be empty.", file=sys.stderr)
        return 1

    # 2. Resolve passphrase
    passphrase_bytes: Optional[bytearray] = None
    try:
        if args.passphrase:
            passphrase_bytes = bytearray(args.passphrase.encode("utf-8"))
        elif "OPKE_PASSPHRASE" in os.environ:
            passphrase_bytes = bytearray(os.environ["OPKE_PASSPHRASE"].encode("utf-8"))
        else:
            passphrase_bytes = prompt_passphrase(confirm=True)
    except Exception as e:
        zero_memory(secret_bytes)
        print(f"[-] Error getting passphrase: {e}", file=sys.stderr)
        return 1

    # 3. Resolve KDF parameters
    profile = PROFILES.get(args.profile.lower(), PROFILES["production"])
    m_kib = args.mem if args.mem is not None else profile["m_kib"]
    t = args.time if args.time is not None else profile["t"]
    p = args.threads if args.threads is not None else profile["p"]

    print(
        f"[*] Deriving keys with Argon2id (m={m_kib} KiB ({m_kib / 1024 / 1024:.2f} GiB), t={t}, p={p})...",
        file=sys.stderr,
    )
    t0 = time.time()

    salt = os.urandom(SALT_LEN)
    try:
        key_chacha, key_aes = derive_key_and_split(
            passphrase=passphrase_bytes,
            salt=salt,
            m_kib=m_kib,
            t=t,
            p=p,
        )
    finally:
        zero_memory(passphrase_bytes)
        del passphrase_bytes

    kdf_elapsed = time.time() - t0
    print(f"[*] Key derivation completed in {kdf_elapsed:.2f}s.", file=sys.stderr)

    # 4. Perform Cascade AEAD Encryption
    try:
        final_ciphertext, tag_aes, nonce_chacha, nonce_aes = encrypt_cascade(
            plaintext=secret_bytes,
            key_chacha=key_chacha,
            key_aes=key_aes,
        )
    finally:
        zero_memory(secret_bytes)
        zero_memory(key_chacha)
        zero_memory(key_aes)
        del secret_bytes, key_chacha, key_aes

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
        with open(args.output, "w", encoding="utf-8") as f:
            if args.raw:
                f.write(raw_b64 + "\n")
            else:
                f.write(paper_output)
        print(f"[+] Encrypted envelope written to: {args.output}", file=sys.stderr)
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

    if args.qr_term:
        print("\n[*] Scan QR code directly from terminal:", file=sys.stderr)
        print_terminal_qr(raw_b64)

    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    """Handles the 'decrypt' command."""
    # 1. Read input envelope
    raw_input: Optional[str] = None
    if args.input:
        raw_input = args.input
    elif args.input_file:
        try:
            with open(args.input_file, "r", encoding="utf-8") as f:
                raw_input = f.read()
        except Exception as e:
            print(f"[-] Error reading envelope file: {e}", file=sys.stderr)
            return 1
    elif not sys.stdin.isatty():
        raw_input = sys.stdin.read()
    else:
        print("[*] Paste your OPKE envelope (or PEM block), then press Ctrl+D:", file=sys.stderr)
        raw_input = sys.stdin.read()

    if not raw_input or not raw_input.strip():
        print("[-] Envelope input is empty.", file=sys.stderr)
        return 1

    # 2. Parse and validate envelope
    try:
        envelope = deserialize_envelope(raw_input)
    except EnvelopeValidationError as e:
        print(f"[-] Invalid OPKE envelope: {e}", file=sys.stderr)
        return 1

    # 3. Read Passphrase
    passphrase_bytes: Optional[bytearray] = None
    try:
        if args.passphrase:
            passphrase_bytes = bytearray(args.passphrase.encode("utf-8"))
        elif "OPKE_PASSPHRASE" in os.environ:
            passphrase_bytes = bytearray(os.environ["OPKE_PASSPHRASE"].encode("utf-8"))
        else:
            passphrase_bytes = prompt_passphrase(confirm=False)
    except Exception as e:
        print(f"[-] Error getting passphrase: {e}", file=sys.stderr)
        return 1

    # 4. Derive keys with envelope's KDF params
    salt, nonce_chacha, nonce_aes, tag_aes, final_ciphertext = envelope.get_decoded_bytes()
    m_kib = envelope.kdf.m_kib
    t = envelope.kdf.t
    p = envelope.kdf.p

    print(
        f"[*] Deriving keys with Argon2id (m={m_kib} KiB ({m_kib / 1024 / 1024:.2f} GiB), t={t}, p={p})...",
        file=sys.stderr,
    )
    t0 = time.time()
    try:
        key_chacha, key_aes = derive_key_and_split(
            passphrase=passphrase_bytes,
            salt=salt,
            m_kib=m_kib,
            t=t,
            p=p,
        )
    finally:
        zero_memory(passphrase_bytes)
        del passphrase_bytes

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
    except CryptoError as e:
        print(f"[-] Cryptographic error: {e}", file=sys.stderr)
        return 1
    finally:
        zero_memory(key_chacha)
        zero_memory(key_aes)
        del key_chacha, key_aes

    # 6. Output plaintext
    if args.output:
        try:
            with open(args.output, "wb") as f:
                f.write(plaintext)
            print(f"[+] Decrypted plaintext written to: {args.output}", file=sys.stderr)
        except Exception as e:
            print(f"[-] Failed to write plaintext to {args.output}: {e}", file=sys.stderr)
            return 1
    else:
        try:
            # Print decoded UTF-8 string if valid, otherwise raw stdout bytes
            sys.stdout.write(plaintext.decode("utf-8"))
            if not plaintext.endswith(b"\n"):
                sys.stdout.write("\n")
            sys.stdout.flush()
        except UnicodeDecodeError:
            sys.stdout.buffer.write(plaintext)
            sys.stdout.buffer.flush()

    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    """Handles the 'inspect' command (displays envelope metadata)."""
    raw_input: Optional[str] = None
    if args.input:
        raw_input = args.input
    elif args.input_file:
        try:
            with open(args.input_file, "r", encoding="utf-8") as f:
                raw_input = f.read()
        except Exception as e:
            print(f"[-] Error reading file: {e}", file=sys.stderr)
            return 1
    elif not sys.stdin.isatty():
        raw_input = sys.stdin.read()
    else:
        print("[-] Please provide an envelope via argument, --input-file, or stdin.", file=sys.stderr)
        return 1

    try:
        envelope = deserialize_envelope(raw_input)
    except EnvelopeValidationError as e:
        print(f"[-] Invalid envelope: {e}", file=sys.stderr)
        return 1

    salt, nonce_chacha, nonce_aes, tag_aes, data = envelope.get_decoded_bytes()
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

    salt = os.urandom(SALT_LEN)
    dummy_passphrase = bytearray(b"OPKE_Benchmark_Passphrase_1234567890")

    m_gib = m_kib / 1024 / 1024
    print(f"[*] Starting Argon2id Benchmark...")
    print(f"[*] Parameters: m={m_kib:,} KiB ({m_gib:.2f} GiB), t={t}, p={p}")
    print(f"[*] Allocating and running KDF, please wait...")

    t0 = time.time()
    try:
        k1, k2 = derive_key_and_split(dummy_passphrase, salt, m_kib=m_kib, t=t, p=p)
        elapsed = time.time() - t0
        zero_memory(k1)
        zero_memory(k2)
    finally:
        zero_memory(dummy_passphrase)

    print(f"[+] Completed in {elapsed:.3f} seconds!")
    print(f"[+] Memory bandwidth evaluated: {(m_gib * t) / elapsed:.2f} GiB-iterations/sec")
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
    p_bm.set_defaults(func=cmd_benchmark)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        sys.exit(args.func(args))
    except KeyboardInterrupt:
        print("\n[!] Aborted by user.", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
