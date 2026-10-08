# OPKE v3.0 (Offline Paper-Key Encryptor)

**OPKE (Offline Paper-Key Encryptor) v3.0** は、VeraCryptの復号パスワードやパスワードマネージャー（1Password、Bitwarden等）のEmergency Kitなどの機密性の極めて高い平文データを、日常記憶しているパスワードから導出した暗号鍵を用いて**紙面印刷用のBase64（PEM形式）およびQRコード**として安全に出力・復元するオフライン暗号化ツールです。

v3.0では**Rust言語による完全ネイティブ実装（`opke-rs`）**となり、単一実行可能バイナリ（`.exe`）での配布、コンパイラ保証された完全なメモリ消去（`zeroize`）、ハードウェアアクセラレーション（AES-NI）、および**エクスプローラーからのダブルクリックでそのまま使える対話型ウィザード**に対応しました。

---

## 1. プロジェクト構成

```text
OPKE/
├── bin/
│   └── opke.exe          # [配布用] ビルド済み単一バイナリ (Windows x86_64)
├── opke-rs/              # OPKE v3.0 Rust ソースコード
│   ├── src/
│   │   ├── core/         # 暗号コア (Argon2id + ChaCha20-Poly1305 + AES-256-GCM)
│   │   ├── envelope/     # エンベロープ管理 (v2/v3対応, PEM形式, Base64)
│   │   ├── security/     # メモリ保護 (Zeroize), 0600セキュアファイルI/O, パスワード非表示入力
│   │   ├── qr/           # QRコード生成 (PNG, SVG, 端末ANSIハーフブロック)
│   │   └── cli/          # CLIサブコマンド & ダブルクリック対応対話ウィザード
│   ├── tests/            # 単一・統合テスト
│   └── Cargo.toml
└── README.md
```

---

## 2. 暗号仕様 (Cryptographic Architecture)

### 2.1 鍵導出関数 (KDF)
- **アルゴリズム**: **Argon2id** (Version 0x13)
- **ソルト**: 16バイト CSPRNG乱数
- **メモリコスト ($m$)**: `8,388,608 KiB` (8 GiB)
- **時間コスト ($t$)**: `64` イテレーション
- **並列度 ($p$)**: `8` スレッド
- **導出鍵長**: `64` バイト (512 ビット)
  - `Key_ChaCha`: 前半32バイト
  - `Key_AES`: 後半32バイト

> [!NOTE]
> 8 GiB / 64 イテレーションの負荷により、オフライン環境で紙面やQRコードを奪われた場合でも、最新GPUクラスタや専用ASICによる総当たり攻撃・辞書攻撃に対して極めて高い耐性を持ちます。

### 2.2 二重AEADカスケード暗号化 (Dual AEAD Cascade)
異なる暗号プリミティブ（ストリーム暗号＋ブロック暗号）を入れ子状に二重適用することで、将来的な暗号解読やアルゴリズムの弱点発覚リスクを排除しています。

1. **第1層 (ChaCha20-Poly1305)**:
   - `Nonce_ChaCha`: 12バイト CSPRNG乱数
   - 平文を暗号化し、中間暗号文と認証タグ（Tag_ChaCha: 16B）を生成。
2. **第2層 (AES-256-GCM)**:
   - `Nonce_AES`: 12バイト CSPRNG乱数
   - 第1層の出力全体（中間暗号文 + Tag_ChaCha）を暗号化し、最終暗号文と認証タグ（Tag_AES: 16B）を生成。

### 2.3 エンベロープ構造 (Envelope Format v3)
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
> **後方互換性**: OPKE v3.0 は、OPKE v2.0 で作成された `"v": 2` のエンベロープも自動検知してシームレスに復号可能です。

---

## 3. 使用方法 (Usage)

### 3.1 ダブルクリック起動（対話ウィザードモード）
Windowsエクスプローラーから `opke.exe` を直接ダブルクリックすると、対話型メニューが起動します：

```text
============================================================
       OPKE v3.0 (Offline Paper-Key Encryptor)             
       オフライン・ペーパーキー暗号化ツール                 
============================================================
 [1] 秘密情報を暗号化 (Encrypt -> Paper Key / QR)
 [2] ペーパーキーを復号 (Decrypt -> Secret)
 [3] エンベロープ情報の確認 (Inspect Envelope)
 [4] 暗号化ベンチマーク (Benchmark)
 [5] 終了 (Exit)
============================================================
操作番号を選択してください [1-5]:
```

- 各ステップの案内に従って秘密平文やパスワードを入力できます。
- 処理終了時も「**Enterキーを押すと終了します**」で一時停止するため、画面が勝手に閉じることはありません。

---

### 3.2 コマンドライン実行 (CLI Mode)

#### 暗号化 (Encrypt)
```bash
# 対話入力で暗号化し、紙面用テキストとQR画像を生成（推奨）
opke encrypt -o paper_key.txt --qr paper_key.png --qr-term

# パイプから暗号化
echo "MyVeraCryptPassword" | opke encrypt -o paper_key.txt

# ファイルから暗号化
opke encrypt -i secret.txt -o paper_key.txt

# プロファイル指定
opke encrypt -o paper_key.txt --profile production # デフォルト (8 GiB, 64 iters)
opke encrypt -o paper_key.txt --profile moderate   # 標準 (1 GiB, 16 iters)
opke encrypt -o paper_key.txt --profile fast       # テスト用 (64 MiB, 2 iters)
```

#### 復号 (Decrypt)
```bash
# ペーパーキーファイルから復号 (画面非表示でパスワード入力)
opke decrypt -i paper_key.txt

# パイプからの復号
cat paper_key.txt | opke decrypt
```

#### エンベロープ情報の確認 (Inspect)
パスフレーズを入力することなく、KDFパラメータや暗号レイヤー等のメタデータを確認できます。
```bash
opke inspect -i paper_key.txt
```

#### ベンチマーク (Benchmark)
お使いのマシン環境で、指定したArgon2idパラメータの所要時間を事前測定します。
```bash
opke benchmark --profile fast
```

---

## 4. ビルド方法 (Build)

```powershell
cd opke-rs
cargo build --release
```
生成物: `opke-rs/target/release/opke.exe` (Windows) または `opke` (Linux/macOS)
外部ランタイムやPython不要の単一バイナリとして、オフラインPCにコピーするだけで即実行できます。

---

## 5. テスト実行 (Test)

```powershell
# Rust版の全単体・統合テスト
cd opke-rs
cargo test
```
