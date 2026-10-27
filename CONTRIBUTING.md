# Contributing to OPKE

Thank you for your interest in contributing to **OPKE (Offline Paper-Key Encryptor)**!

As a security-sensitive cryptographic utility, OPKE prioritizes correctness, minimalism, and verifiable safety above feature velocity. Please review the following guidelines before submitting issues or pull requests.

---

## 1. Guiding Principles

1. **Security & Rigor**: Cryptographic logic must remain mathematically sound, constant-time where applicable, and properly verified against memory corruption and edge conditions.
2. **KISS & Minimalism**: Avoid unnecessary abstractions, speculative dependencies, or complex platform-specific hooks. Smaller, verifiable code is better security.
3. **Reproducibility**: When reporting bugs or proposing changes, concrete test cases or reproduction scripts are required.
4. **Objective Documentation**: Avoid marketing buzzwords or sensationalist claims. Maintain precise, factual technical documentation.

---

## 2. Reporting Issues

* **Security Vulnerabilities**:  
  Do **NOT** open public issues for security vulnerabilities. Please report them privately via GitHub Private Vulnerability Reporting (see [SECURITY.md](SECURITY.md)).
* **Bug Reports**:  
  Please use the [Bug Report template](.github/ISSUE_TEMPLATE/bug_report.yml) and provide the exact command, environment details, and minimal reproducible steps.
* **Feature Requests**:  
  Open a feature request describing the use case and cryptographic rationale.

---

## 3. Development & Pull Requests

### 3.1 Prerequisites
* Modern stable Rust toolchain (`rustup update stable`)
* Formatter and linter components: `rustup component add rustfmt clippy`

### 3.2 Local Verification Workflow
Before submitting a pull request, ensure all local checks pass:

```bash
cd opke-rs

# 1. Format check
cargo fmt --all -- --check

# 2. Strict linter check (zero warnings tolerated)
cargo clippy --all-targets --all-features -- -D warnings

# 3. Unit and integration test suite
cargo test --all-targets --all-features
```

### 3.3 Commit & PR Guidelines
* **Commit Messages**: Use concise, conventional commit prefixes (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `ci:`).
* **Commit Signatures**: Commit signing with SSH or GPG is enforced for merging into the `master` branch.
* **Single Responsibility**: Keep PRs focused on a single change. Avoid bundling unrelated refactorings with feature additions or bug fixes.
