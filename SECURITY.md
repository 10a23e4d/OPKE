# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in OPKE, please report it privately:

1. **GitHub Private Vulnerability Reporting (Recommended)**:  
   Navigate to the **Security** tab of this repository, select **Advisories**, and click **"Report a vulnerability"**.
2. **Email Disclosure**:  
   If Private Vulnerability Reporting is unavailable, please open an issue requesting a private security contact channel without including sensitive exploit details.

Please do **NOT** report security vulnerabilities via public GitHub Issues or Discussions.

---

## Threat Model & Scope Boundary

To maintain high cryptographic rigor and avoid speculative/unactionable reports (Security Theater), OPKE defines clear threat boundaries based on its project guidelines ([GEMINI.md](GEMINI.md)).

### In Scope (Addressed as Vulnerabilities)
* **Cryptographic Flaws**:
  * Key derivation deficiencies or improper salt/entropy handling.
  * Nonce reuse, missing AAD commitments, or improper AEAD / cipher cascade usage.
* **Input Validation & Memory Safety**:
  * Denial of Service (DoS), unhandled panics, or memory undefined behavior (UB) caused by malformed ciphertexts, invalid keys, or corrupted input formats (PEM/JSON).
* **Sensitive Data Leakage**:
  * Unintentional leakage of plaintexts or keys to disk, crash logs, or external channels during normal encryption/decryption operations.

### Out of Scope (Will Be Closed as "Expected / Non-Vulnerability")
* **Compromised Host Environments**:
  * Exploits relying on existing root/administrator malware, arbitrary memory snooping of running processes, malicious OS kernels, or physical/hardware eavesdropping (e.g., cold boot attacks, hardware bus interception).
* **Self-Destructive User Actions**:
  * Intentional malformed CLI parameter combinations designed solely to cause a process abort, or self-severed stdout/stderr pipes.
* **Build / CI / Test Infrastructure**:
  * Formatting styles, build script nuances, or test harnesses that do not affect the security guarantees of the shipped binary.

---

## Requirements for Vulnerability Reports

Every valid vulnerability report must adhere to the following principles:
1. **Proof of Concept (PoC) Required**: Reports must provide a minimal reproducible test case (e.g., specific input data or test script) demonstrating actual unintended behavior, plain text leakage, or undefined behavior. Speculative claims without reproducible proof will not be accepted.
2. **KISS & Minimalism**: Recommended fixes should avoid over-engineering or unnecessary low-level OS hooks. Standard, well-audited crates and clean, reduced code lines are prioritized.

---

## Supported Versions

Only the latest release is actively supported with security patches:

| Version | Supported |
| :--- | :--- |
| `v3.0.x` (Latest) | :white_check_mark: |
| `< v3.0.0` | :x: |
