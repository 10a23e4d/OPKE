"""OPKE Envelope Serialization, Deserialization, and Validation.

Handles JSON envelope structure according to OPKE v2.0 specification,
compact serialization, Base64 encoding, paper formatting (PEM-style), and strict validation.
"""

import base64
from dataclasses import asdict, dataclass
import hmac
import json
import re
from typing import Any, Dict, List, Tuple

from opke.security import MAX_SECRET_BYTES

PEM_HEADER = "-----BEGIN OPKE ENVELOPE-----"
PEM_FOOTER = "-----END OPKE ENVELOPE-----"

# Validation limits
MAX_M_KIB = 67108864  # 64 GiB max memory limit to prevent DoS
MIN_M_KIB = 8         # Argon2 minimum
MAX_T = 1000          # 1000 iterations max limit
MIN_T = 1
MAX_P = 256           # 256 threads max
MIN_P = 1
MIN_CIPHERTEXT_BYTES = 17  # 1-byte plaintext + 16-byte Poly1305 tag
MAX_CIPHERTEXT_BYTES = MAX_SECRET_BYTES + 16  # 64 MiB plaintext + 16-byte Poly1305 tag
MAX_ENVELOPE_CHARS = 160 * 1024 * 1024  # 160 MiB sanity limit for envelope strings (supports 64 MiB payloads with double Base64 and PEM formatting)
MIN_DATA_B64_CHARS = ((MIN_CIPHERTEXT_BYTES + 2) // 3) * 4
MAX_DATA_B64_CHARS = ((MAX_CIPHERTEXT_BYTES + 2) // 3) * 4

ALLOWED_ENVELOPE_KEYS = {"v", "kdf", "cipher", "data"}
ALLOWED_KDF_KEYS = {"name", "m_kib", "t", "p", "salt"}
ALLOWED_CIPHER_KEYS = {"layers", "nonce_chacha", "nonce_aes", "tag_aes"}


class EnvelopeValidationError(ValueError):
    """Raised when an envelope fails structure or cryptographic validation."""
    pass


def _reject_duplicate_keys(ordered_pairs):
    """Ensures JSON payload contains no duplicate keys."""
    d = {}
    for k, v in ordered_pairs:
        if k in d:
            raise EnvelopeValidationError(f"Duplicate key in envelope JSON: {k!r}")
        d[k] = v
    return d


@dataclass
class KDFParams:
    name: str
    m_kib: int
    t: int
    p: int
    salt: str  # Base64-encoded 16 bytes


@dataclass
class CipherParams:
    layers: List[str]
    nonce_chacha: str  # Base64-encoded 12 bytes
    nonce_aes: str     # Base64-encoded 12 bytes
    tag_aes: str       # Base64-encoded 16 bytes


@dataclass
class OPKEEnvelope:
    v: int
    kdf: KDFParams
    cipher: CipherParams
    data: str          # Base64-encoded final ciphertext

    def to_dict(self) -> Dict[str, Any]:
        return {
            "v": self.v,
            "kdf": asdict(self.kdf),
            "cipher": asdict(self.cipher),
            "data": self.data,
        }

    def to_compact_json(self) -> str:
        """Serializes envelope to compact JSON string without whitespace."""
        return json.dumps(self.to_dict(), separators=(",", ":"))

    def to_base64_payload(self) -> str:
        """Serializes envelope to a single-line Base64 string."""
        compact_json = self.to_compact_json().encode("utf-8")
        return base64.b64encode(compact_json).decode("ascii")

    def to_paper_format(self, line_length: int = 64) -> str:
        """Formats the Base64 payload into paper-friendly PEM-style wrapped text."""
        if type(line_length) is not int or line_length < 16 or line_length > 1024:
            raise ValueError(f"Invalid line_length: {line_length} (must be integer between 16 and 1024)")
        b64_payload = self.to_base64_payload()
        lines = [b64_payload[i:i + line_length] for i in range(0, len(b64_payload), line_length)]
        return f"{PEM_HEADER}\n" + "\n".join(lines) + f"\n{PEM_FOOTER}\n"

    def get_decoded_bytes(self) -> Tuple[bytes, bytes, bytes, bytes, bytes]:
        """Decodes all base64-encoded cryptographic fields to bytes.

        Returns:
            Tuple[bytes, bytes, bytes, bytes, bytes]:
                (salt, nonce_chacha, nonce_aes, tag_aes, final_ciphertext)
        """
        try:
            salt = base64.b64decode(self.kdf.salt, validate=True)
            nonce_chacha = base64.b64decode(self.cipher.nonce_chacha, validate=True)
            nonce_aes = base64.b64decode(self.cipher.nonce_aes, validate=True)
            tag_aes = base64.b64decode(self.cipher.tag_aes, validate=True)
            data = base64.b64decode(self.data, validate=True)
        except Exception as e:
            raise EnvelopeValidationError(f"Base64 decoding failed for cryptographic fields: {e}")

        return salt, nonce_chacha, nonce_aes, tag_aes, data


def create_envelope(
    salt: bytes,
    m_kib: int,
    t: int,
    p: int,
    nonce_chacha: bytes,
    nonce_aes: bytes,
    tag_aes: bytes,
    final_ciphertext: bytes,
) -> OPKEEnvelope:
    """Creates a strongly validated OPKEEnvelope instance from raw cryptographic bytes."""
    if not isinstance(salt, (bytes, bytearray)) or len(salt) != 16:
        raise ValueError(f"Salt length must be 16 bytes, got {len(salt) if hasattr(salt, '__len__') else type(salt).__name__}")
    if type(m_kib) is not int or not (MIN_M_KIB <= m_kib <= MAX_M_KIB):
        raise ValueError(f"Invalid or out-of-range m_kib: {m_kib} (range: {MIN_M_KIB}-{MAX_M_KIB})")
    if type(t) is not int or not (MIN_T <= t <= MAX_T):
        raise ValueError(f"Invalid or out-of-range t: {t} (range: {MIN_T}-{MAX_T})")
    if type(p) is not int or not (MIN_P <= p <= MAX_P):
        raise ValueError(f"Invalid or out-of-range p: {p} (range: {MIN_P}-{MAX_P})")
    if m_kib < 8 * p:
        raise ValueError(f"Memory cost too low: {m_kib} KiB (must be >= 8 * p = {8 * p} KiB)")
    if not isinstance(nonce_chacha, (bytes, bytearray)) or len(nonce_chacha) != 12:
        raise ValueError(f"Nonce_ChaCha length must be 12 bytes, got {len(nonce_chacha) if hasattr(nonce_chacha, '__len__') else type(nonce_chacha).__name__}")
    if not isinstance(nonce_aes, (bytes, bytearray)) or len(nonce_aes) != 12:
        raise ValueError(f"Nonce_AES length must be 12 bytes, got {len(nonce_aes) if hasattr(nonce_aes, '__len__') else type(nonce_aes).__name__}")
    if hmac.compare_digest(nonce_chacha, nonce_aes):
        raise ValueError("Nonce_ChaCha and Nonce_AES must be distinct.")
    if not isinstance(tag_aes, (bytes, bytearray)) or len(tag_aes) != 16:
        raise ValueError(f"Tag_AES length must be 16 bytes, got {len(tag_aes) if hasattr(tag_aes, '__len__') else type(tag_aes).__name__}")
    if not isinstance(final_ciphertext, (bytes, bytearray)):
        raise TypeError(f"Ciphertext must be bytes or bytearray, got {type(final_ciphertext).__name__}")
    if len(final_ciphertext) == 0:
        raise ValueError("Ciphertext length cannot be empty.")
    if len(final_ciphertext) > MAX_CIPHERTEXT_BYTES:
        raise ValueError(f"Ciphertext length exceeds maximum allowed size ({MAX_CIPHERTEXT_BYTES} bytes).")

    return OPKEEnvelope(
        v=2,
        kdf=KDFParams(
            name="argon2id",
            m_kib=m_kib,
            t=t,
            p=p,
            salt=base64.b64encode(salt).decode("ascii"),
        ),
        cipher=CipherParams(
            layers=["chacha20-poly1305", "aes-256-gcm"],
            nonce_chacha=base64.b64encode(nonce_chacha).decode("ascii"),
            nonce_aes=base64.b64encode(nonce_aes).decode("ascii"),
            tag_aes=base64.b64encode(tag_aes).decode("ascii"),
        ),
        data=base64.b64encode(final_ciphertext).decode("ascii"),
    )


def serialize_envelope(envelope: OPKEEnvelope, paper_format: bool = False) -> str:
    """Serializes an OPKEEnvelope to string (paper format or raw Base64)."""
    if not isinstance(envelope, OPKEEnvelope):
        raise TypeError(f"Expected OPKEEnvelope instance, got {type(envelope).__name__}")
    if paper_format:
        return envelope.to_paper_format()
    return envelope.to_base64_payload()


def deserialize_envelope(raw_input: str) -> OPKEEnvelope:
    """Parses and strictly validates an envelope from string input.

    Accepts:
    - PEM-style wrapped Base64 text
    - Single-line or multi-line Base64 string
    - Raw JSON string

    Raises:
        EnvelopeValidationError: If input format, structure, or cryptographic fields are invalid.
    """
    if len(raw_input) > MAX_ENVELOPE_CHARS:
        raise EnvelopeValidationError(f"Envelope input exceeds maximum allowed size ({MAX_ENVELOPE_CHARS} chars).")

    text = raw_input.strip()
    if not text:
        raise EnvelopeValidationError("Input is empty.")

    # 1. Strip PEM header/footer if present, validating both are present and strictly bounding input
    has_header = PEM_HEADER in text
    has_footer = PEM_FOOTER in text
    if has_header or has_footer:
        if not (has_header and has_footer):
            raise EnvelopeValidationError("Malformed PEM envelope: incomplete header or footer.")
        if text.count(PEM_HEADER) > 1 or text.count(PEM_FOOTER) > 1:
            raise EnvelopeValidationError("Multiple PEM envelope markers detected; ambiguous input.")
        if not text.startswith(PEM_HEADER) or not text.endswith(PEM_FOOTER):
            raise EnvelopeValidationError("Malformed PEM envelope: unexpected data outside encapsulation boundary.")
        text = text[len(PEM_HEADER):-len(PEM_FOOTER)].strip()

    # Remove all whitespace/newlines from candidate string
    cleaned = "".join(text.split())

    # 2. Try parsing as JSON first (in case raw JSON was supplied)
    json_data = None
    if cleaned.startswith("{") and cleaned.endswith("}"):
        try:
            json_data = json.loads(
                cleaned,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=lambda c: (_ for _ in ()).throw(EnvelopeValidationError(f"Invalid JSON constant: {c}")),
            )
        except EnvelopeValidationError:
            raise
        except Exception as e:
            raise EnvelopeValidationError(f"Invalid JSON string: {e}")
    else:
        # Otherwise, decode Base64 to JSON
        try:
            raw_bytes = base64.b64decode(cleaned, validate=True)
            json_str = raw_bytes.decode("utf-8")
            json_data = json.loads(
                json_str,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=lambda c: (_ for _ in ()).throw(EnvelopeValidationError(f"Invalid JSON constant: {c}")),
            )
        except EnvelopeValidationError:
            raise
        except Exception as e:
            raise EnvelopeValidationError(f"Failed to decode Base64 envelope payload: {e}")

    # 3. Validate envelope schema
    if not isinstance(json_data, dict):
        raise EnvelopeValidationError("Envelope payload must be a JSON object.")

    if set(json_data.keys()) != ALLOWED_ENVELOPE_KEYS:
        unknown = set(json_data.keys()) - ALLOWED_ENVELOPE_KEYS
        missing = ALLOWED_ENVELOPE_KEYS - set(json_data.keys())
        if missing:
            raise EnvelopeValidationError(f"Envelope missing required fields: {missing}")
        if unknown:
            raise EnvelopeValidationError(f"Envelope contains unrecognized fields: {unknown}")

    # Version check (strictly int, not bool)
    v = json_data.get("v")
    if type(v) is not int or v != 2:
        raise EnvelopeValidationError(f"Unsupported envelope version: {v}. Expected version 2.")

    # KDF check
    kdf_raw = json_data.get("kdf")
    if not isinstance(kdf_raw, dict):
        raise EnvelopeValidationError("Envelope missing 'kdf' object.")

    if set(kdf_raw.keys()) != ALLOWED_KDF_KEYS:
        unknown = set(kdf_raw.keys()) - ALLOWED_KDF_KEYS
        missing = ALLOWED_KDF_KEYS - set(kdf_raw.keys())
        if missing:
            raise EnvelopeValidationError(f"Envelope KDF missing required fields: {missing}")
        if unknown:
            raise EnvelopeValidationError(f"Envelope KDF contains unrecognized fields: {unknown}")

    if kdf_raw.get("name") != "argon2id":
        raise EnvelopeValidationError(f"Unsupported KDF algorithm: {kdf_raw.get('name')}. Expected 'argon2id'.")

    m_kib = kdf_raw.get("m_kib")
    t = kdf_raw.get("t")
    p = kdf_raw.get("p")
    salt_b64 = kdf_raw.get("salt")

    if type(m_kib) is not int or not (MIN_M_KIB <= m_kib <= MAX_M_KIB):
        raise EnvelopeValidationError(f"Invalid or out-of-range m_kib: {m_kib} (range: {MIN_M_KIB}-{MAX_M_KIB})")
    if type(t) is not int or not (MIN_T <= t <= MAX_T):
        raise EnvelopeValidationError(f"Invalid or out-of-range t: {t} (range: {MIN_T}-{MAX_T})")
    if type(p) is not int or not (MIN_P <= p <= MAX_P):
        raise EnvelopeValidationError(f"Invalid or out-of-range p: {p} (range: {MIN_P}-{MAX_P})")
    if m_kib < 8 * p:
        raise EnvelopeValidationError(f"Invalid or out-of-range m_kib: {m_kib} (Argon2 requires m_kib >= 8 * p = {8 * p})")
    if not isinstance(salt_b64, str):
        raise EnvelopeValidationError("Envelope missing 'salt' string in 'kdf'.")

    # Cipher check
    cipher_raw = json_data.get("cipher")
    if not isinstance(cipher_raw, dict):
        raise EnvelopeValidationError("Envelope missing 'cipher' object.")

    if set(cipher_raw.keys()) != ALLOWED_CIPHER_KEYS:
        unknown = set(cipher_raw.keys()) - ALLOWED_CIPHER_KEYS
        missing = ALLOWED_CIPHER_KEYS - set(cipher_raw.keys())
        if missing:
            raise EnvelopeValidationError(f"Envelope cipher missing required fields: {missing}")
        if unknown:
            raise EnvelopeValidationError(f"Envelope cipher contains unrecognized fields: {unknown}")

    layers = cipher_raw.get("layers")
    if layers != ["chacha20-poly1305", "aes-256-gcm"]:
        raise EnvelopeValidationError(f"Unsupported cipher layers: {layers}. Expected ['chacha20-poly1305', 'aes-256-gcm'].")

    nonce_chacha_b64 = cipher_raw.get("nonce_chacha")
    nonce_aes_b64 = cipher_raw.get("nonce_aes")
    tag_aes_b64 = cipher_raw.get("tag_aes")

    if not isinstance(nonce_chacha_b64, str):
        raise EnvelopeValidationError("Envelope missing 'nonce_chacha'.")
    if not isinstance(nonce_aes_b64, str):
        raise EnvelopeValidationError("Envelope missing 'nonce_aes'.")
    if not isinstance(tag_aes_b64, str):
        raise EnvelopeValidationError("Envelope missing 'tag_aes'.")

    # Sanity upper limit to prevent DoS on fixed-length metadata fields
    if len(salt_b64) > 1024 or len(nonce_chacha_b64) > 1024 or len(nonce_aes_b64) > 1024 or len(tag_aes_b64) > 1024:
        raise EnvelopeValidationError("Cryptographic metadata field exceeds maximum allowed size.")

    data_b64 = json_data.get("data")
    if not isinstance(data_b64, str) or not data_b64:
        raise EnvelopeValidationError("Envelope missing or empty 'data' field.")
    if len(data_b64) > MAX_DATA_B64_CHARS:
        raise EnvelopeValidationError(f"Envelope 'data' field exceeds maximum allowed size ({MAX_DATA_B64_CHARS} chars).")

    # 4. Construct envelope object and validate decoded byte lengths
    envelope = OPKEEnvelope(
        v=2,
        kdf=KDFParams(name="argon2id", m_kib=m_kib, t=t, p=p, salt=salt_b64),
        cipher=CipherParams(
            layers=layers,
            nonce_chacha=nonce_chacha_b64,
            nonce_aes=nonce_aes_b64,
            tag_aes=tag_aes_b64,
        ),
        data=data_b64,
    )

    salt, nonce_chacha, nonce_aes, tag_aes, data = envelope.get_decoded_bytes()
    if len(salt) != 16:
        raise EnvelopeValidationError(f"Salt length must be 16 bytes, got {len(salt)}")
    if len(nonce_chacha) != 12:
        raise EnvelopeValidationError(f"Nonce_ChaCha length must be 12 bytes, got {len(nonce_chacha)}")
    if len(nonce_aes) != 12:
        raise EnvelopeValidationError(f"Nonce_AES length must be 12 bytes, got {len(nonce_aes)}")
    if hmac.compare_digest(nonce_chacha, nonce_aes):
        raise EnvelopeValidationError("Nonce_ChaCha and Nonce_AES must be distinct.")
    if len(tag_aes) != 16:
        raise EnvelopeValidationError(f"Tag_AES length must be 16 bytes, got {len(tag_aes)}")
    if len(data) == 0:
        raise EnvelopeValidationError("Ciphertext data cannot be empty.")
    if len(data) > MAX_CIPHERTEXT_BYTES:
        raise EnvelopeValidationError(f"Ciphertext data exceeds maximum allowed size ({MAX_CIPHERTEXT_BYTES} bytes).")

    return envelope
