[English](README.md) | **日本語**

# OPKE v3.0.2 (Offline Paper-Key Encryptor)

**OPKE (Offline Paper-Key Encryptor) v3.0.2** は、VeraCryptの復号パスワードやパスワードマネージャー（1Password、Bitwarden等）のEmergency Kitなどの機密性の極めて高い平文データを、日常記憶しているパスワードから導出した暗号鍵を用いて**紙面印刷用のBase64（PEM形式）およびQRコード**として安全に出力・復元するオフライン暗号化ツールです。

v3.0以降では**Rust言語による完全ネイティブ実装（`opke-rs`）**となり、単一実行可能バイナリ（`.exe`）での配布、コンパイラ保証された完全なメモリ消去（`zeroize`）、物理メモリロック（`VirtualLock`/`mlock`によるスワップアウト防止）、ハードウェアアクセラレーション（AES-NI）、および**エクスプローラーからのダブルクリックでそのまま使える対話型ウィザード**に対応しました。

v3.0.2では、全74件の包括的セキュリティ監査に基づく深層改修に加え、CI完全自動化、形式検証（Kani）、ファジング（cargo-fuzz）が統合されています。

---

## 1. プロジェクト構成

```text
OPKE/
├── opke-rs/              # OPKE v3.0.2 Rust ソースコード
│   ├── src/
│   │   ├── core/         # 暗号コア (Argon2id + ChaCha20-Poly1305 + AES-256-GCM + AAD)
│   │   ├── envelope/     # エンベロープ管理 (v2/v3対応, PEM形式, Base64事前検証)
│   │   ├── security/     # メモリ保護 (VirtualLock, Zeroize), ACL制御, パスワード非表示入力
│   │   ├── qr/           # QRコード生成 (PNG, SVG, 端末ANSIハイコントラスト表示)
│   │   └── cli/          # CLIサブコマンド & ダブルクリック対応対話ウィザード
│   ├── tests/            # 単体・統合・セキュリティ回帰テスト (計35テスト)
│   └── Cargo.toml
├── LICENSE-MIT           # MIT License
├── LICENSE-APACHE        # Apache License 2.0
├── README.md             # 英語版ドキュメント (English)
└── README_ja.md          # 日本語版ドキュメント (本書)
```

---

## 2. 暗号仕様 (Cryptographic Architecture)

### 2.1 鍵導出関数 (KDF)
- **アルゴリズム**: **Argon2id** (Version 0x13)
- **正規化**: パスフレーズを投入前に Unicode NFC 正規化（macOS vs Windows/Linux 間の復号互換性を保証）
- **ソルト**: 16バイト CSPRNG乱数
- **メモリコスト ($m$)**: `8,388,608 KiB` (8 GiB)
- **時間コスト ($t$)**: `64` イテレーション
- **並列度 ($p$)**: `8` スレッド
- **導出鍵長**: `64` バイト (512 ビット)
  - `Key_ChaCha`: 前半32バイト（物理 RAM ロック＋使用後即時ゼロ消去）
  - `Key_AES`: 後半32バイト（物理 RAM ロック＋使用後即時ゼロ消去）

> [!NOTE]
> 8 GiB / 64 イテレーションの負荷により、オフライン環境で紙面やQRコードを奪われた場合でも、最新GPUクラスタや専用ASICによる総当たり攻撃・辞書攻撃に対して極めて高い耐性を持ちます。

### 2.2 二重AEADカスケード暗号化 (Dual AEAD Cascade with AAD)
異なる暗号プリミティブ（ストリーム暗号＋ブロック暗号）を入れ子状に二重適用し、エンベロープヘッダのメタデータを関連データ（AAD）として暗号学的にバインドしています。

1. **第1層 (ChaCha20-Poly1305)**:
   - `Nonce_ChaCha`: 12バイト CSPRNG乱数
   - 平文を暗号化し、中間暗号文と認証タグ（Tag_ChaCha: 16B）を生成。
2. **第2層 (AES-256-GCM)**:
   - `Nonce_AES`: 12バイト CSPRNG乱数
   - `AAD`: `opke:v=3:kdf=argon2id:...`（バージョンやKDFパラメータの改ざん・ロールバックを遮断）
   - 第1層の出力全体（中間暗号文 + Tag_ChaCha）を暗号化し、最終暗号文と認証タグ（Tag_AES: 16B）を生成。
3. **認証エラーの統一**:
   - 復号時、いずれの層でタグ不一致が発生しても同一のエラーメッセージを返却し、解読オラクル（サイドチャネル攻撃）を排除。

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
> **後方互換性とダウングレード防止**: OPKE v3.0.2 は旧 v2 エンベロープも解析可能ですが、暗号学的ダウングレード攻撃を防ぐため、v2 暗号文の復号には明示的な `--allow-v2` オプションの指定が必須となっています。

---

## 3. 使用方法 (Usage)

### 3.1 ダブルクリック起動（対話ウィザードモード）
Windowsエクスプローラーから `opke.exe` を直接ダブルクリックすると、対話型メニューが起動します：

```text
============================================================
       OPKE v3.0.2 (Offline Paper-Key Encryptor)             
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
- 復号結果を画面表示する際は、覗き見（ショルダーサーフィン）防止の確認警告が表示されます。
- 処理終了時も「**Enterキーを押すと終了します**」で一時停止するため、画面が勝手に閉じることはありません。

---

### 3.2 コマンドライン実行 (CLI Mode)

#### 暗号化 (Encrypt)
```bash
# 対話入力で暗号化し、紙面用テキストとQR画像を生成（推奨）
opke encrypt -o paper_key.txt --qr paper_key.png --qr-term

# パイプから暗号化（特殊パス "-" の入出力対応）
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

# PEM ブロック文字列を直接引数に渡して復号（ハイフン付き引数に対応）
opke decrypt "-----BEGIN OPKE ENVELOPE-----..."

# パイプからの復号
cat paper_key.txt | opke decrypt

# 旧 v2 エンベロープの復号（明示的フラグが必要）
opke decrypt -i legacy_paper_key.txt --allow-v2
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
# Rust版の全単体・統合・セキュリティ回帰テスト (計35件)
cd opke-rs
cargo test
```

---

## 6. ライセンス (License)

本プロジェクトは、Rust エコシステムの標準に準拠した以下のデュアルライセンス（Dual License）の下で公開されています。利用者の選択に応じて、いずれかのライセンス条件の下で利用・再配布・改変が可能です：

- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE))
- **MIT License** ([LICENSE-MIT](LICENSE-MIT))

---

## 7. セキュリティ注意事項 & 完全免責事項 (Security Notice & Disclaimer)

> [!CAUTION]
> **本ソフトウェアのご利用にあたり、以下の事項を必ずご確認ください：**
>
> 1. **「現状有姿（AS IS）」での提供と無保証**:
>    本ソフトウェアはオープンソースソフトウェアとして「現状有姿（AS IS）」で提供され、商品性、特定目的への適合性、セキュリティの完全性、不具合・バグの不存在を含む一切の明示的・黙示的保証を行いません。
>
> 2. **暗号学的安全性および実装瑕疵の完全免責**:
>    本ソフトウェアは多層防御および監査に基づく堅牢なセキュリティ設計を施していますが、将来的な暗号アルゴリズムの理論的破断、ハードウェア/コンパイラ起因のサイドチャネル、未発見の実装上の欠陥等により暗号データが解読・漏洩・破損した場合であっても、作者および著作権者は契約責任、不法行為責任（過失を含む）、その他いかなる法理においても一切の損害賠償責任・補償責任を負いません。
>
> 3. **パスフレーズの自己管理責任**:
>    本ツールにはバックドア（裏口）やマスターキーは一切存在しません。万が一パスフレーズを紛失・失念した場合、作者を含め世界中の誰も平文データを救出・復元することは数学的・物理的に不可能です。
>
> 4. **端末・実行環境の健全性**:
>    マルウェア、キーロガー、不正なメモリ監視ツール等に感染した環境で本ツールを実行した場合の平文やパスフレーズの漏洩について、本ツールは防護を保証できません。極秘情報を扱う際は、ネットワークから完全に隔離されたクリーンなオフライン端末環境でご利用ください。
>
> 5. **物理的媒体の劣化と分散保管**:
>    紙面印刷のインク褪色、水濡れ、物理的破損、QRコードの汚損等に備え、重要な秘密情報については複数箇所への地理的分散保管を行うことを強く推奨します。物理的媒体の損傷等による復号不能について、作者は一切責任を負いません。
