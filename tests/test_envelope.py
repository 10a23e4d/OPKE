"""Unit tests for OPKE envelope serialization, parsing, and validation."""

import base64
import json
import os
import pytest

from opke.envelope import (
    OPKEEnvelope,
    create_envelope,
    serialize_envelope,
    deserialize_envelope,
    EnvelopeValidationError,
    PEM_HEADER,
    PEM_FOOTER,
)


def sample_envelope_data():
    return {
        "salt": os.urandom(16),
        "m_kib": 8388608,
        "t": 64,
        "p": 8,
        "nonce_chacha": os.urandom(12),
        "nonce_aes": os.urandom(12),
        "tag_aes": os.urandom(16),
        "final_ciphertext": b"encrypted_payload_bytes_here",
    }


def test_create_and_serialize_envelope():
    data = sample_envelope_data()
    envelope = create_envelope(**data)

    assert envelope.v == 2
    assert envelope.kdf.name == "argon2id"
    assert envelope.kdf.m_kib == 8388608
    assert envelope.kdf.t == 64
    assert envelope.kdf.p == 8
    assert envelope.cipher.layers == ["chacha20-poly1305", "aes-256-gcm"]

    compact_json = envelope.to_compact_json()
    parsed_json = json.loads(compact_json)
    assert parsed_json["v"] == 2
    assert parsed_json["kdf"]["m_kib"] == 8388608

    b64_payload = envelope.to_base64_payload()
    assert isinstance(b64_payload, str)

    paper_text = envelope.to_paper_format()
    assert paper_text.startswith(PEM_HEADER)
    assert paper_text.strip().endswith(PEM_FOOTER)

    # Check line wrapping in paper format
    lines = paper_text.strip().split("\n")
    # All inner lines should be at most 64 chars
    for line in lines[1:-1]:
        assert len(line) <= 64


def test_deserialize_formats():
    data = sample_envelope_data()
    envelope = create_envelope(**data)

    # 1. From paper format
    paper_text = envelope.to_paper_format()
    env1 = deserialize_envelope(paper_text)
    assert env1 == envelope
    assert env1.get_decoded_bytes() == (
        data["salt"],
        data["nonce_chacha"],
        data["nonce_aes"],
        data["tag_aes"],
        data["final_ciphertext"],
    )

    # 2. From raw Base64 payload
    b64_payload = envelope.to_base64_payload()
    env2 = deserialize_envelope(b64_payload)
    assert env2 == envelope

    # 3. From raw JSON string
    json_str = envelope.to_compact_json()
    env3 = deserialize_envelope(json_str)
    assert env3 == envelope


def test_deserialize_invalid_inputs():
    with pytest.raises(EnvelopeValidationError, match="Input is empty"):
        deserialize_envelope("   ")

    with pytest.raises(EnvelopeValidationError, match="Malformed PEM"):
        deserialize_envelope(f"{PEM_HEADER}\nincomplete_content")

    with pytest.raises(EnvelopeValidationError, match="Failed to decode Base64"):
        deserialize_envelope("Not-valid-base64-payload!!!")


def test_validation_schema_errors():
    valid = create_envelope(**sample_envelope_data()).to_dict()

    # Invalid version
    d = json.loads(json.dumps(valid))
    d["v"] = 1
    with pytest.raises(EnvelopeValidationError, match="Unsupported envelope version"):
        deserialize_envelope(json.dumps(d))

    # Invalid KDF name
    d = json.loads(json.dumps(valid))
    d["kdf"]["name"] = "scrypt"
    with pytest.raises(EnvelopeValidationError, match="Unsupported KDF algorithm"):
        deserialize_envelope(json.dumps(d))

    # Memory cost too small
    d = json.loads(json.dumps(valid))
    d["kdf"]["m_kib"] = 4
    with pytest.raises(EnvelopeValidationError, match="Invalid or out-of-range m_kib"):
        deserialize_envelope(json.dumps(d))

    # Time cost too small
    d = json.loads(json.dumps(valid))
    d["kdf"]["t"] = 0
    with pytest.raises(EnvelopeValidationError, match="Invalid or out-of-range t"):
        deserialize_envelope(json.dumps(d))

    # Parallelism out of range
    d = json.loads(json.dumps(valid))
    d["kdf"]["p"] = 500
    with pytest.raises(EnvelopeValidationError, match="Invalid or out-of-range p"):
        deserialize_envelope(json.dumps(d))

    # Invalid layers
    d = json.loads(json.dumps(valid))
    d["cipher"]["layers"] = ["aes-256-gcm"]
    with pytest.raises(EnvelopeValidationError, match="Unsupported cipher layers"):
        deserialize_envelope(json.dumps(d))


def test_validation_byte_length_errors():
    valid = create_envelope(**sample_envelope_data()).to_dict()

    # Invalid salt length (15 bytes instead of 16)
    d = json.loads(json.dumps(valid))
    d["kdf"]["salt"] = base64.b64encode(os.urandom(15)).decode("ascii")
    with pytest.raises(EnvelopeValidationError, match="Salt length must be 16 bytes"):
        deserialize_envelope(json.dumps(d))

    # Invalid nonce_chacha length (11 bytes instead of 12)
    d = json.loads(json.dumps(valid))
    d["cipher"]["nonce_chacha"] = base64.b64encode(os.urandom(11)).decode("ascii")
    with pytest.raises(EnvelopeValidationError, match="Nonce_ChaCha length must be 12 bytes"):
        deserialize_envelope(json.dumps(d))

    # Invalid nonce_aes length (16 bytes instead of 12)
    d = json.loads(json.dumps(valid))
    d["cipher"]["nonce_aes"] = base64.b64encode(os.urandom(16)).decode("ascii")
    with pytest.raises(EnvelopeValidationError, match="Nonce_AES length must be 12 bytes"):
        deserialize_envelope(json.dumps(d))

    # Invalid tag_aes length (12 bytes instead of 16)
    d = json.loads(json.dumps(valid))
    d["cipher"]["tag_aes"] = base64.b64encode(os.urandom(12)).decode("ascii")
    with pytest.raises(EnvelopeValidationError, match="Tag_AES length must be 16 bytes"):
        deserialize_envelope(json.dumps(d))
