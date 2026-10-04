\# 要件定義書: Offline Paper-Key Encryptor (OPKE) v2.0



\## 1. システム概要

\- \*\*目的\*\*: 

&#x20; VeraCryptの長大な復号鍵やパスワードマネージャーのEmergency Kit（平文）を、日常的に記憶しているパスワードを用いて超高負荷暗号化し、紙面印刷用のBase64文字列（およびQRコード）として安全に出力・復元する。

\- \*\*実行環境\*\*: Python 3.10以上（Windows / macOS / Linux クロスプラットフォーム対応）

\- \*\*主要外部依存\*\*: 

&#x20; - `argon2-cffi` (Argon2id KDF実装)

&#x20; - `cryptography` (PyCA製: AES-256-GCM および ChaCha20-Poly1305 実装)



\---



\## 2. 機能要件



\### 2.1 暗号化モード (Encrypt Mode)

1\. \*\*入力\*\*:

&#x20;  - 秘密情報（平文テキスト: 標準入力または対話プロンプト）

&#x20;  - パスフレーズ（日常パスワード: 画面エコーバックなしで2回入力・一致検証）

2\. \*\*鍵導出処理 (KDF)\*\*:

&#x20;  - アルゴリズム: \*\*Argon2id\*\* (Version 0x13)

&#x20;  - ソルト: CSPRNG (`os.urandom(16)`) による16バイトの暗号論的乱数

&#x20;  - メモリコスト ($m$): `8,388,608 KiB` (8 GiB)

&#x20;  - 時間コスト ($t$): `64` イテレーション

&#x20;  - 並列度 ($p$): `8` スレッド

&#x20;  - 導出鍵長: `64` バイト (512 ビット)

3\. \*\*二重AEADカスケード暗号化処理\*\*:

&#x20;  - 導出鍵を前後32バイトずつ分割:

&#x20;    - `Key\_ChaCha`: 前半32バイト

&#x20;    - `Key\_AES`: 後半32バイト

&#x20;  - 平文を以下の2層構造で多重暗号化:

&#x20;    1. \*\*第1層 (ChaCha20-Poly1305)\*\*:

&#x20;       - Nonce\_ChaCha: CSPRNGによる12バイト乱数

&#x20;       - 平文を暗号化し、中間暗号文と認証タグ (Tag\_ChaCha: 16B) を生成。

&#x20;    2. \*\*第2層 (AES-256-GCM)\*\*:

&#x20;       - Nonce\_AES: CSPRNGによる12バイト乱数

&#x20;       - 第1層の出力全体（中間暗号文 + Tag\_ChaCha）を暗号化し、最終暗号文と認証タグ (Tag\_AES: 16B) を生成。

4\. \*\*出力フォーマット\*\*:

&#x20;  - メタデータと暗号文を単一のエンベロープ（JSON構造等）に統合し、Base64エンコードして出力。

&#x20;  ```json

&#x20;  {

&#x20;    "v": 2,

&#x20;    "kdf": {

&#x20;      "name": "argon2id",

&#x20;      "m\_kib": 8388608,

&#x20;      "t": 64,

&#x20;      "p": 8,

&#x20;      "salt": "<Base64\_Salt\_16B>"

&#x20;    },

&#x20;    "cipher": {

&#x20;      "layers": \["chacha20-poly1305", "aes-256-gcm"],

&#x20;      "nonce\_chacha": "<Base64\_12B>",

&#x20;      "nonce\_aes": "<Base64\_12B>",

&#x20;      "tag\_aes": "<Base64\_16B>"

&#x20;    },

&#x20;    "data": "<Base64\_FinalCiphertext>"

&#x20;  }


### 2.2 復号モード (Decrypt Mode)

1. **入力**:
   - 暗号化エンベロープ（Base64文字列、PEM形式テキスト、またはQRコード/ファイル/標準入力）
   - パスフレーズ（日常パスワード: 画面エコーバックなしで入力）

2. **エンベロープ解析・検証**:
   - Base64デコードおよびJSONパース
   - バージョン整合性検証 (`v == 2`)
   - アルゴリズムおよびレイヤー検証 (`kdf.name == "argon2id"`, `cipher.layers == ["chacha20-poly1305", "aes-256-gcm"]`)
   - バイト長検証（Salt: 16B, Nonces: 各12B, Tag: 16B）

3. **鍵再導出処理 (KDF)**:
   - エンベロープ内のKDFパラメータ (`m_kib`, `t`, `p`, `salt`) と入力パスフレーズからArgon2id (v0x13) により64バイト鍵を再導出
   - 鍵分割:
     - `Key_ChaCha`: 前半32バイト
     - `Key_AES`: 後半32バイト

4. **二重AEADカスケード復号・認証処理**:
   - **第2層復号 (AES-256-GCM)**:
     - `Key_AES`, `Nonce_AES`, `Tag_AES` を用いて `data` を復号・認証。
     - 認証失敗時は即時エラー終了（改ざん検知またはパスワード不一致）。
     - 成功時、第1層データ（中間暗号文 + Tag_ChaCha）を取得。
   - **第1層復号 (ChaCha20-Poly1305)**:
     - `Key_ChaCha`, `Nonce_ChaCha` を用いて第1層データを復号・認証。
     - 認証失敗時は即時エラー終了。
     - 成功時、元の平文秘密情報を復元。

5. **出力**:
   - 復元された平文テキストを出力（標準出力または指定ファイル）。

---

### 2.3 紙面出力およびQRコード仕様

1. **紙面印刷テキスト形式**:
   - コンパクトJSONエンベロープをBase64化し、64文字ごとに改行。
   - PEMヘッダー/フッターを付与:
     ```text
     -----BEGIN OPKE ENVELOPE-----
     ... (Base64 payload, 64 chars/line) ...
     -----END OPKE ENVELOPE-----
     ```
2. **QRコード画像出力**:
   - 印刷用PNGおよびベクターSVG形式に対応。
   - エラー訂正レベル: Level H (最大30%の損傷復元) または Level Q (最大25%復元)。
3. **コンソールQR表示**:
   - ANSI/Unicodeハーフブロック文字を用いたターミナル上での直接スキャン用表示に対応。

---

## 3. CLI インターフェース仕様

```bash
# 暗号化
opke encrypt [SECRET] [-i INPUT_FILE] [-p PASSPHRASE] [-o OUTPUT] [--profile PROFILE] [--qr QR_PATH] [--qr-term]

# 復号
opke decrypt [INPUT] [-i INPUT_FILE] [-p PASSPHRASE] [-o OUTPUT]

# エンベロープ情報確認 (パスワード不要)
opke inspect [INPUT] [-i INPUT_FILE]

# ベンチマーク
opke benchmark [--profile PROFILE]
```

### プロファイル
- `production` (デフォルト): 8 GiB (8,388,608 KiB), 64 iterations, 8 threads
- `moderate`: 1 GiB (1,048,576 KiB), 16 iterations, 4 threads
- `fast` / `test`: 64 MiB (65,536 KiB), 2 iterations, 2 threads

---

## 4. セキュリティ要件

1. **メモリ保護**: パスワードおよび中間鍵素材（`bytearray`）は処理完了直後に上書きゼロ初期化（`zero_memory`）を行い、メモリダンプやスワップからの漏洩を防止する。
2. **定数時間認証**: AEADプリミティブ内部の定数時間MAC検証によりタイミング攻撃を防止する。
3. **DoS防止**: エンベロープ内のKDFパラメータに対する安全上限チェック（最大メモリ64GiB、最大イテレーション1000等）を行い、不正エンベロープによるリソース枯渇を防止する。
4. **画面エコーバック防止**: `getpass` による非表示入力および2重入力確認。

---

## 5. テスト・検証要件

- 単体テスト (`pytest`) による以下項目の自動検証:
  1. 鍵導出の決定性と分離（ChaCha/AES鍵の独立性）
  2. 暗号化・復号の往復完全性（ASCII、日本語UTF-8、長大バイナリ）
  3. Nonce、Tag、Ciphertextの1ビット改ざん検知（第1層/第2層）
  4. 誤パスワード時の認証拒絶
  5. 不正・規格外エンベロープ（フォーマット、型、範囲、長さ）の拒絶
  6. QRコード（PNG/SVG）生成妥当性
  7. CLIコマンド群（encrypt, decrypt, inspect, benchmark, パイプ入出力）のE2E動作
