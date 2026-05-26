"""AES-256-CBC + HMAC-SHA256 encryption matching Bitwarden's EncString format."""
import hashlib
import hmac
import os
import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

_BACKEND = default_backend()


def derive_master_key(password: str, email: str, iterations: int = 600_000) -> bytes:
    """PBKDF2-SHA256 key derivation — same parameters as Bitwarden clients."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        email.strip().lower().encode("utf-8"),
        iterations,
    )


def stretch_master_key(master_key: bytes) -> tuple[bytes, bytes]:
    """Expand master key into (enc_key, mac_key) via HKDF-Expand."""
    enc_key = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"enc", backend=_BACKEND).derive(master_key)
    mac_key = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"mac", backend=_BACKEND).derive(master_key)
    return enc_key, mac_key


def _check_mac(mac_key: bytes, iv: bytes, ciphertext: bytes, mac: bytes) -> None:
    expected = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected):
        raise ValueError("HMAC verification failed — wrong key or corrupted data")


def decrypt_enc_string(enc_string: str, enc_key: bytes, mac_key: bytes) -> bytes:
    """Decrypt a Bitwarden EncString (format: 2.ciphertext_b64|iv_b64|mac_b64)."""
    if "." not in enc_string:
        raise ValueError(f"Not a valid EncString: {enc_string[:20]!r}")
    prefix, rest = enc_string.split(".", 1)
    if prefix != "2":
        raise ValueError(f"Unsupported EncString type: {prefix!r} (only AES-256-CBC type 2 supported)")

    parts = rest.split("|")
    if len(parts) != 3:
        raise ValueError(f"Malformed EncString: expected 3 pipe-separated parts, got {len(parts)}")

    ciphertext = base64.b64decode(parts[0])
    iv = base64.b64decode(parts[1])
    mac = base64.b64decode(parts[2])

    _check_mac(mac_key, iv, ciphertext, mac)

    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=_BACKEND)
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def decrypt_string(enc_string: str, enc_key: bytes, mac_key: bytes) -> str:
    return decrypt_enc_string(enc_string, enc_key, mac_key).decode("utf-8")


def encrypt_bytes(plaintext: bytes, enc_key: bytes, mac_key: bytes) -> str:
    """Encrypt raw bytes into Bitwarden EncString format."""
    iv = os.urandom(16)

    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=_BACKEND)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    mac = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()

    return (
        f"2.{base64.b64encode(ciphertext).decode()}"
        f"|{base64.b64encode(iv).decode()}"
        f"|{base64.b64encode(mac).decode()}"
    )


def encrypt_string(plaintext: str, enc_key: bytes, mac_key: bytes) -> str:
    return encrypt_bytes(plaintext.encode("utf-8"), enc_key, mac_key)


def decrypt_profile_key(profile_key_enc: str, stretched_enc: bytes, stretched_mac: bytes) -> tuple[bytes, bytes]:
    """
    Decrypt the vault profile's symmetric key.

    The server stores the 64-byte user symmetric key encrypted with the
    stretched master key. Returns (enc_key, mac_key) — first 32 and last 32
    bytes of the decrypted blob.
    """
    raw = decrypt_enc_string(profile_key_enc, stretched_enc, stretched_mac)
    if len(raw) != 64:
        raise ValueError(f"Expected 64-byte symmetric key after decryption, got {len(raw)} bytes")
    return raw[:32], raw[32:]
