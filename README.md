# OPKE v2.0 (Offline Paper-Key Encryptor)

**OPKE (Offline Paper-Key Encryptor) v2.0** は、VeraCryptの復号パスワードやパスワードマネージャー（1Password、Bitwarden等）のEmergency Kitなどの機密性の極めて高い平文データを、日常記憶しているパスワードから導出した暗号鍵を用いて**紙面印刷用のBase64およびQRコード**として安全に出力・復元するオフライン暗号化ツールです。

---

## 1. 暗号仕様 (Cryptographic Architecture)

### 1.1 鍵導出関数 (KDF)
- **アルゴリズム**: **Argon2id** (Version 0x13)
- **ソルト**: 16バイト CSPRNG (`os.urandom(16)`)
- **メモリコスト ($m$)**: `8,388,608 KiB` (8 GiB)
- **時間コスト ($t$)**: `64` イテレーション
- **並列度 ($p$)**: `8` スレッド
- **導出鍵長**: `64` バイト (512 ビット)
  - `Key_ChaCha`: 前半32バイト
  - `Key_AES`: 後半32バイト

> [!NOTE]
> 8 GiB / 64 イテレーションの負荷により、オフライン環境で紙面やQRコードを奪われた場合でも、最新GPUクラスタや専用ASICによる総当たり攻撃・辞書攻撃に対して極めて高い耐性を持ちます。

### 1.2 二重AEADカスケード暗号化 (Dual AEAD Cascade)
異なる暗号プリミティブ（ストリーム暗号＋ブロック暗号）を入れ子状に二重適用することで、将来的な暗号解読やアルゴリズムの弱点発覚リスクを排除しています。

1. **第1層 (ChaCha20-Poly1305)**:
   - `Nonce_ChaCha`: 12バイト CSPRNG乱数
   - 平文を暗号化し、中間暗号文と認証タグ（Tag_ChaCha: 16B）を生成。
2. **第2層 (AES-256-GCM)**:
   - `Nonce_AES`: 12バイト CSPRNG乱数
   - 第1層の出力全体（中間暗号文 + Tag_ChaCha）を暗号化し、最終暗号文と認証タグ（Tag_AES: 16B）を生成。

### 1.3 エンベロープ構造 (Envelope Format)
```json
{
  "v": 2,
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
出力時は上記JSONをコンパクト化してBase64エンコードし、紙面印刷に適した64文字改行PEM形式またはQRコード画像（PNG/SVG）として保存されます。

---

## 2. インストール (Installation)

### 必要要件
- Python 3.10以上
- Windows / macOS / Linux

### セットアップ
```bash
# 仮想環境の作成と有効化
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# パッケージのインストール
pip install -e .
```

---

## 3. 使用方法 (Usage)

### 3.1 暗号化 (Encrypt)

#### 対話的入力（推奨: ターミナル履歴にパスワードを残さない）
```bash
opke encrypt -o paper_key.txt --qr paper_key.png --qr-term
```
- 秘密平文の入力（画面非表示）
- パスフレーズの入力（確認のため2回入力、画面非表示）
- 完了後、紙面用テキストファイル `paper_key.txt` と印刷用QRコード画像 `paper_key.png` が生成され、ターミナル上にもQRコードが表示されます。

#### パイプ・ファイル入力
```bash
# パイプから秘密情報を暗号化
echo -n "MySuperSecretVeraCryptKey123" | opke encrypt -o paper_key.txt

# ファイルから暗号化
opke encrypt -i /path/to/emergency_kit.txt -o paper_key.txt
```

#### プロファイル選択
- `--profile production` (デフォルト): 8 GiB, 64 iters, 8 threads
- `--profile moderate`: 1 GiB, 16 iters, 4 threads
- `--profile fast` (テスト用): 64 MiB, 2 iters, 2 threads

---

### 3.2 復号 (Decrypt)

#### 対話的復号
```bash
opke decrypt -i paper_key.txt
```
パスフレーズを入力すると、認証タグが検証され、平文が出力されます。

#### パイプ・クリップボードからの復号
```bash
cat paper_key.txt | opke decrypt
```

---

### 3.3 エンベロープ情報の確認 (Inspect)
パスフレーズを入力することなく、エンベロープのKDFパラメータや暗号レイヤー等のメタデータを確認できます。
```bash
opke inspect -i paper_key.txt
```

---

### 3.4 ベンチマーク (Benchmark)
お使いのマシン環境で、指定したArgon2idパラメータの実行時間を事前測定します。
```bash
opke benchmark --profile production
```

---

## 4. セキュリティ上の推奨事項 (Security Notes)

> [!WARNING]
> - **オフライン環境での実行**: 暗号化および復号は、可能な限りネットワークから切断されたエアギャップ環境（またはライブLinux USB環境等）で実施してください。
> - **印刷用紙の保管**: 感熱紙（レシート用紙など）は熱や光で印字が消える恐れがあるため、普通紙レーザープリンターでの印刷を強く推奨します。
> - **メモリ保護**: OPKEはメモリ上のパスワードおよび派生鍵素材を処理直後にゼロクリア（`zero_memory`）します。
