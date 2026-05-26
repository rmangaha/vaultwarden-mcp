"""Unit tests for the crypto module."""
import base64

import pytest

from vaultwarden_mcp.crypto import (
    decrypt_enc_string,
    decrypt_profile_key,
    decrypt_string,
    derive_master_key,
    encrypt_bytes,
    encrypt_string,
    stretch_master_key,
)

ENC_KEY = b"\x01" * 32
MAC_KEY = b"\x02" * 32


class TestEncryptDecryptRoundtrip:
    def test_basic_roundtrip(self):
        enc = encrypt_string("hello, vault!", ENC_KEY, MAC_KEY)
        assert decrypt_string(enc, ENC_KEY, MAC_KEY) == "hello, vault!"

    def test_encstring_format(self):
        enc = encrypt_string("test", ENC_KEY, MAC_KEY)
        assert enc.startswith("2.")
        parts = enc.split(".", 1)[1].split("|")
        assert len(parts) == 3
        # All three parts must be valid base64
        for p in parts:
            base64.b64decode(p)

    def test_unique_iv_per_call(self):
        a = encrypt_string("same plaintext", ENC_KEY, MAC_KEY)
        b = encrypt_string("same plaintext", ENC_KEY, MAC_KEY)
        assert a != b  # Different IVs produce different EncStrings

    def test_empty_string(self):
        enc = encrypt_string("", ENC_KEY, MAC_KEY)
        assert decrypt_string(enc, ENC_KEY, MAC_KEY) == ""

    def test_unicode_roundtrip(self):
        plaintext = "パスワード123 \U0001f511 ñoño"
        enc = encrypt_string(plaintext, ENC_KEY, MAC_KEY)
        assert decrypt_string(enc, ENC_KEY, MAC_KEY) == plaintext

    def test_long_string(self):
        plaintext = "x" * 10_000
        enc = encrypt_string(plaintext, ENC_KEY, MAC_KEY)
        assert decrypt_string(enc, ENC_KEY, MAC_KEY) == plaintext

    def test_bytes_roundtrip(self):
        data = bytes(range(256))
        enc = encrypt_bytes(data, ENC_KEY, MAC_KEY)
        assert decrypt_enc_string(enc, ENC_KEY, MAC_KEY) == data

    def test_newlines_and_special_chars(self):
        plaintext = "line1\nline2\ttabbed\r\n<script>alert('xss')</script>"
        enc = encrypt_string(plaintext, ENC_KEY, MAC_KEY)
        assert decrypt_string(enc, ENC_KEY, MAC_KEY) == plaintext


class TestIntegrityChecks:
    def test_wrong_mac_key_raises(self):
        enc = encrypt_string("secret", ENC_KEY, MAC_KEY)
        with pytest.raises(ValueError, match="HMAC"):
            decrypt_string(enc, ENC_KEY, b"\xff" * 32)

    def test_wrong_enc_key_raises(self):
        enc = encrypt_string("secret", ENC_KEY, MAC_KEY)
        # MAC still passes (mac_key is correct), but decrypting with the wrong
        # enc_key produces garbage bytes that fail PKCS7 unpadding.
        with pytest.raises(ValueError):
            decrypt_string(enc, b"\xff" * 32, MAC_KEY)

    def test_tampered_ciphertext_raises(self):
        enc = encrypt_string("secret", ENC_KEY, MAC_KEY)
        prefix, rest = enc.split(".", 1)
        parts = rest.split("|")
        raw_ct = base64.b64decode(parts[0])
        tampered = bytearray(raw_ct)
        tampered[0] ^= 0xFF
        parts[0] = base64.b64encode(bytes(tampered)).decode()
        tampered_enc = f"{prefix}.{'|'.join(parts)}"
        with pytest.raises(ValueError, match="HMAC"):
            decrypt_string(tampered_enc, ENC_KEY, MAC_KEY)

    def test_unsupported_type_raises(self):
        with pytest.raises(ValueError, match="Unsupported"):
            decrypt_string("0.abc|def|ghi", ENC_KEY, MAC_KEY)

    def test_malformed_encstring_raises(self):
        with pytest.raises(ValueError):
            decrypt_string("2.nodivider", ENC_KEY, MAC_KEY)

    def test_not_encstring_raises(self):
        with pytest.raises(ValueError):
            decrypt_string("plaintext", ENC_KEY, MAC_KEY)


class TestKeyDerivation:
    def test_deterministic(self):
        k1 = derive_master_key("password", "user@example.com")
        k2 = derive_master_key("password", "user@example.com")
        assert k1 == k2
        assert len(k1) == 32

    def test_email_normalised_to_lowercase(self):
        k1 = derive_master_key("password", "User@EXAMPLE.COM")
        k2 = derive_master_key("password", "user@example.com")
        assert k1 == k2

    def test_email_stripped_of_whitespace(self):
        k1 = derive_master_key("password", "  user@example.com  ")
        k2 = derive_master_key("password", "user@example.com")
        assert k1 == k2

    def test_different_passwords_differ(self):
        k1 = derive_master_key("password1", "user@example.com")
        k2 = derive_master_key("password2", "user@example.com")
        assert k1 != k2

    def test_different_emails_differ(self):
        k1 = derive_master_key("password", "alice@example.com")
        k2 = derive_master_key("password", "bob@example.com")
        assert k1 != k2

    def test_custom_iterations(self):
        k_default = derive_master_key("password", "user@example.com", 600_000)
        k_custom = derive_master_key("password", "user@example.com", 100_000)
        assert k_default != k_custom


class TestStretchMasterKey:
    def test_produces_two_different_keys(self):
        master = derive_master_key("password", "user@example.com")
        enc, mac = stretch_master_key(master)
        assert enc != mac
        assert len(enc) == 32
        assert len(mac) == 32

    def test_deterministic(self):
        master = derive_master_key("password", "user@example.com")
        enc1, mac1 = stretch_master_key(master)
        enc2, mac2 = stretch_master_key(master)
        assert enc1 == enc2
        assert mac1 == mac2

    def test_different_masters_differ(self):
        m1 = derive_master_key("password1", "user@example.com")
        m2 = derive_master_key("password2", "user@example.com")
        enc1, mac1 = stretch_master_key(m1)
        enc2, mac2 = stretch_master_key(m2)
        assert enc1 != enc2
        assert mac1 != mac2


class TestDecryptProfileKey:
    def test_roundtrip_profile_key(self):
        # Simulate a 64-byte user symmetric key stored encrypted with stretched keys
        fake_symmetric_key = bytes(range(64))
        stretched_enc, stretched_mac = stretch_master_key(b"\xAA" * 32)

        # Encrypt the fake key as the server would store it
        from vaultwarden_mcp.crypto import encrypt_bytes
        stored = encrypt_bytes(fake_symmetric_key, stretched_enc, stretched_mac)

        # Decrypt it back
        enc_key, mac_key = decrypt_profile_key(stored, stretched_enc, stretched_mac)
        assert enc_key == fake_symmetric_key[:32]
        assert mac_key == fake_symmetric_key[32:]

    def test_wrong_length_raises(self):
        stretched_enc, stretched_mac = stretch_master_key(b"\xAA" * 32)
        bad_key = b"short"
        stored = encrypt_bytes(bad_key, stretched_enc, stretched_mac)
        with pytest.raises(ValueError, match="64-byte"):
            decrypt_profile_key(stored, stretched_enc, stretched_mac)
