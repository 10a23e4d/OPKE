**English** | [日本語](README_ja.md)

# OPKE v3.0.1 (Offline Paper-Key Encryptor)

**OPKE (Offline Paper-Key Encryptor) v3.0.1** is a military-grade, standalone offline encryption tool designed to safeguard ultra-sensitive secrets—such as VeraCrypt master passwords, password manager emergency recovery kits (1Password, Bitwarden), and root seed keys—by converting them into **cold-storage paper keys (PEM format)** and **high-density QR codes** backed by memory-hard key derivation.

Starting with v3.0, OPKE is completely natively implemented in **Rust (`opke-rs`)** as a zero-dependency standalone binary (`.exe`), featuring compiler-guaranteed memory zeroization (`zeroize`), kernel physical memory locking (`VirtualLock` on Windows / `mlock` on Unix to prevent swapping secrets to `pagefile.sys`), hardware-accelerated AES-NI, and an **interactive guided wizard for seamless double-click execution from Windows Explorer**.

In v3.0.1, comprehensive architectural remediations for all 74 security audit findings have been integrated (cryptographic AAD envelope binding, Unicode NFC normalization, atomic creation, mandatory file locking, and process memory scrubbing).

---

## 1. Project Layout

```text
OPKE/
├── opke-rs/              # OPKE v3.0.1 Rust source code
│   ├── src/
│   │   ├── core/         # Cryptographic engine (Argon2id + ChaCha20-Poly1305 + AES-256-GCM + AAD)
│   │   ├── envelope/     # Envelope format (v2/v3 support, PEM encoding, Base64 pre-bounds)
│   │   ├── security/     # OS security (VirtualLock, Zeroize, ACLs, hidden prompt, PEB scrub)
│   │   ├── qr/           # QR code generation (PNG, SVG, high-contrast ANSI terminal rendering)
│   │   └── cli/          # CLI subcommands & double-click interactive wizard
│   ├── tests/            # Test suites: unit, crypto, and security regression (35 tests total)
│   └── Cargo.toml
├── LICENSE-MIT           # MIT License
├── LICENSE-APACHE        # Apache License 2.0
├── README.md             # English documentation (this file)
└── README_ja.md          # Japanese documentation (日本語版)
```

---

## 2. Cryptographic Architecture

### 2.1 Key Derivation Function (KDF)
- **Algorithm**: **Argon2id** (Version 0x13)
- **Normalization**: Passphrases are normalized to Unicode NFC prior to KDF hashing, ensuring cross-platform decryption parity between macOS (decomposed NFD) and Windows/Linux (precomposed NFC).
- **Salt**: 16-byte cryptographically secure CSPRNG random bytes.
- **Memory Cost ($m$)**: `8,388,608 KiB` (8 GiB physical RAM)
- **Time Cost ($t$)**: `64` iterations
- **Parallelism ($p$)**: `8` threads
- **Derived Key Material**: `64` bytes (512 bits)
  - `Key_ChaCha`: First 32 bytes (locked in physical RAM, wiped immediately on drop)
  - `Key_AES`: Second 32 bytes (locked in physical RAM, wiped immediately on drop)

> [!NOTE]
> The massive computational complexity of 8 GiB / 64 iterations ensures that even if physical paper keys or QR codes are seized, brute-force dictionary attacks remain economically and physically intractable against modern GPU clusters and custom ASIC hardware.

### 2.2 Dual AEAD Cascade with Associated Data (AAD)
Applies nested AEAD ciphers with complementary mathematical foundations (stream cipher + block cipher), cryptographically binding envelope metadata into Associated Data (AAD):

1. **Layer 1 (ChaCha20-Poly1305)**:
   - `Nonce_ChaCha`: 12-byte CSPRNG random nonce.
   - Encrypts raw secret plaintext, generating intermediate ciphertext and authentication tag (`Tag_ChaCha`: 16B).
2. **Layer 2 (AES-256-GCM)**:
   - `Nonce_AES`: 12-byte CSPRNG random nonce.
   - `AAD`: `opke:v=3:kdf=argon2id:...` (cryptographically commits to envelope version, KDF cost parameters, and layer identifiers).
   - Encrypts Layer 1 payload (`IntermediateCiphertext` + `Tag_ChaCha`), generating final ciphertext and authentication tag (`Tag_AES`: 16B).
3. **Unified Decryption Error**:
   - Decryption failures across both layers return a single, indistinguishable error message to eliminate side-channel and multi-layer decryption oracles.

### 2.3 Envelope Format (v3)
```json
{
  "v": 3,
  "kdf": {
    "name": "argon2id",
    "m_kib": 8388608,
    "t": 64,
    "p": 8,
    "salt": "<Base64_Salt_16B>"
  },
  "cipher": {
    "layers": ["chacha20-poly1305", "aes-256-gcm"],
    "nonce_chacha": "<Base64_12B>",
    "nonce_aes": "<Base64_12B>",
    "tag_aes": "<Base64_16B>"
  },
  "data": "<Base64_FinalCiphertext>"
}
```

> [!TIP]
> **Backward Compatibility & Downgrade Defense**: OPKE v3.0.1 can parse legacy v2 envelopes. However, to prevent cryptographic downgrade attacks, decrypting v2 envelopes requires an explicit `--allow-v2` command-line flag.

---

## 3. Usage

### 3.1 Double-Click Execution (Interactive Wizard Mode)
Simply double-click `opke.exe` in Windows Explorer to launch the interactive terminal wizard:

```text
============================================================
       OPKE v3.0.1 (Offline Paper-Key Encryptor)             
       Offline Paper-Key Encryption Utility                 
============================================================
 [1] Encrypt Secret (Encrypt -> Paper Key / QR)
 [2] Decrypt Paper Key (Decrypt -> Secret)
 [3] Inspect Envelope Metadata (Inspect Envelope)
 [4] Benchmark Hardware (Benchmark)
 [5] Exit
============================================================
Select operation [1-5]:
```

- Guides you through secret entry and hidden passphrase prompts.
- Displays shoulder-surfing warnings before printing decrypted plaintext to the console.
- Automatically pauses with *"Press Enter to exit..."* upon completion, preventing the console window from closing prematurely.

---

### 3.2 Command-Line Interface (CLI Mode)

#### Encrypting Secrets
```bash
# Interactive secret prompt to paper file and QR image (Recommended)
opke encrypt -o paper_key.txt --qr paper_key.png --qr-term

# Piped input from standard input (supports "-" special path)
echo "MyVeraCryptMasterPassword" | opke encrypt -o paper_key.txt

# Encrypting an existing file
opke encrypt -i secret.txt -o paper_key.txt

# Selecting predefined KDF profiles
opke encrypt -o paper_key.txt --profile production # Default: 8 GiB RAM, 64 iters
opke encrypt -o paper_key.txt --profile moderate   # Standard: 1 GiB RAM, 16 iters
opke encrypt -o paper_key.txt --profile fast       # Fast testing: 64 MiB RAM, 2 iters
```

#### Decrypting Secrets
```bash
# Decrypt from paper key file (hidden passphrase prompt)
opke decrypt -i paper_key.txt

# Decrypt directly from a PEM block string argument (hyphen-safe argument parsing)
opke decrypt "-----BEGIN OPKE ENVELOPE-----..."

# Decrypt from a UNIX pipe
cat paper_key.txt | opke decrypt

# Decrypting legacy v2 envelopes (requires explicit opt-in)
opke decrypt -i legacy_paper_key.txt --allow-v2
```

#### Inspecting Envelope Metadata
Inspect envelope KDF parameters and cipher layers without prompting for passphrases:
```bash
opke inspect -i paper_key.txt
```

#### Benchmarking Hardware
Measure Argon2id processing time for target profiles on your local machine:
```bash
opke benchmark --profile fast
```

---

## 4. Building from Source

```powershell
cd opke-rs
cargo build --release
```
Artifact: `opke-rs/target/release/opke.exe` (Windows) or `opke` (Linux/macOS).  
Compiled with Link-Time Optimization (`lto = true`), symbol stripping (`strip = true`), and runtime integer overflow checks (`overflow-checks = true`).

---

## 5. Running Tests

```powershell
# Executes full unit, cryptographic, and security regression test suites (35 tests)
cd opke-rs
cargo test
```

---

## 6. License

This project is dual-licensed under:

- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE))
- **MIT License** ([LICENSE-MIT](LICENSE-MIT))

You may choose to use, redistribute, or modify this software under the terms of either license.

---

## 7. Security Notice & Limitation of Liability

> [!CAUTION]
> **Please read the following disclaimer carefully prior to using this software:**
>
> 1. **"AS IS" Provision and Disclaimer of Warranty**:  
>    This software is provided on an "AS IS" basis, without warranties or conditions of any kind, either express or implied, including, without limitation, any warranties or conditions of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A PARTICULAR PURPOSE.
>
> 2. **Limitation of Liability for Cryptographic and Implementation Defects**:  
>    While OPKE adheres to strict defense-in-depth principles and comprehensive security audit remediations, neither the authors nor contributors shall be liable under any legal theory (whether in contract, tort, negligence, or otherwise) for any direct, indirect, incidental, consequential, or punitive damages—including data loss, exposure, recovery failure, or business interruption—arising from the use or inability to use this software, theoretical breaks in underlying cryptographic primitives, hardware/compiler side-channels, or undiscovered implementation flaws.
>
> 3. **Passphrase Irrecoverability**:  
>    OPKE contains zero backdoors, master keys, or recovery escrow. If you lose or forget your passphrase, recovery of your encrypted plaintext is mathematically and physically impossible.
>
> 4. **Host Environment Integrity**:  
>    OPKE cannot protect against compromised host environments infected with keyloggers, screen scrapers, memory injectors, or hardware monitoring implants. Ultra-sensitive operations should always be performed on dedicated, air-gapped offline systems.
>
> 5. **Physical Media Degradation and Redundancy**:  
>    Physical paper degrades over time (ink fading, physical tearing, moisture). Users are strongly advised to store paper keys in multiple geographically dispersed, waterproof, and fire-resistant locations.
