"""OPKE Envelope Serialization, Deserialization, and Validation.

Handles JSON envelope structure according to OPKE v2.0 specification,
compact serialization, Base64 encoding, paper formatting (PEM-style), and strict validation.
"""

import base64
from dataclasses import asdict, dataclass
import json
import re
from typing import Any, Dict, List, Tuple


PEM_HEADER = "-----BEGIN OPKE ENVELOPE-----"
PEM_FOOTER = "-----END OPKE ENVELOPE-----"

# Validation limits
MAX_M_KIB = 67108864  # 64 GiB max memory limit to prevent DoS
MIN_M_KIB = 8         # Argon2 minimum
MAX_T = 1000          # 1000 iterations max limit
MIN_T = 1
MAX_P = 256           # 256 threads max
MIN_P = 1


class EnvelopeValidationError(ValueError):
    """Raised when an envelope fails structure or cryptographic validation."""
    pass


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
    text = raw_input.strip()
    if not text:
        raise EnvelopeValidationError("Input is empty.")

    # 1. Strip PEM header/footer if present
    if PEM_HEADER in text:
        pattern = rf"{re.escape(PEM_HEADER)}\s*(.*?)\s*{re.escape(PEM_FOOTER)}"
        match = re.search(pattern, text, re.DOTALL)
        if match:
            text = match.group(1)
        else:
            raise EnvelopeValidationError("Malformed PEM envelope markers.")

    # Remove all whitespace/newlines from candidate string
    cleaned = "".join(text.split())

    # 2. Try parsing as JSON first (in case raw JSON was supplied)
    json_data = None
    if cleaned.startswith("{") and cleaned.endswith("}"):
        try:
            json_data = json.loads(cleaned)
        except Exception as e:
            raise EnvelopeValidationError(f"Invalid JSON string: {e}")
    else:
        # Otherwise, decode Base64 to JSON
        try:
            raw_bytes = base64.b64decode(cleaned, validate=True)
            json_str = raw_bytes.decode("utf-8")
            json_data = json.loads(json_str)
        except Exception as e:
            raise EnvelopeValidationError(f"Failed to decode Base64 envelope payload: {e}")

    # 3. Validate envelope schema
    if not isinstance(json_data, dict):
        raise EnvelopeValidationError("Envelope payload must be a JSON object.")

    # Version check
    v = json_data.get("v")
    if v != 2:
        raise EnvelopeValidationError(f"Unsupported envelope version: {v}. Expected version 2.")

    # KDF check
    kdf_raw = json_data.get("kdf")
    if not isinstance(kdf_raw, dict):
        raise EnvelopeValidationError("Envelope missing 'kdf' object.")

    if kdf_raw.get("name") != "argon2id":
        raise EnvelopeValidationError(f"Unsupported KDF algorithm: {kdf_raw.get('name')}. Expected 'argon2id'.")

    m_kib = kdf_raw.get("m_kib")
    t = kdf_raw.get("t")
    p = kdf_raw.get("p")
    salt_b64 = kdf_raw.get("salt")

    if not (isinstance(m_kib, int) and MIN_M_KIB <= m_kib <= MAX_M_KIB):
        raise EnvelopeValidationError(f"Invalid or out-of-range m_kib: {m_kib} (range: {MIN_M_KIB}-{MAX_M_KIB})")
    if not (isinstance(t, int) and MIN_T <= t <= MAX_T):
        raise EnvelopeValidationError(f"Invalid or out-of-range t: {t} (range: {MIN_T}-{MAX_T})")
    if not (isinstance(p, int) and MIN_P <= p <= MAX_P):
        raise EnvelopeValidationError(f"Invalid or out-of-range p: {p} (range: {MIN_P}-{MAX_P})")
    if not isinstance(salt_b64, str):
        raise EnvelopeValidationError("Envelope missing 'salt' string in 'kdf'.")

    # Cipher check
    cipher_raw = json_data.get("cipher")
    if not isinstance(cipher_raw, dict):
        raise EnvelopeValidationError("Envelope missing 'cipher' object.")

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

    data_b64 = json_data.get("data")
    if not isinstance(data_b64, str) or not data_b64:
        raise EnvelopeValidationError("Envelope missing or empty 'data' field.")

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
    if len(tag_aes) != 16:
        raise EnvelopeValidationError(f"Tag_AES length must be 16 bytes, got {len(tag_aes)}")
    if len(data) == 0:
        raise EnvelopeValidationError("Ciphertext data cannot be empty.")

    return envelope
