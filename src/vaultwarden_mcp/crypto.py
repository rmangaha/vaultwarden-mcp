"""AES-256-CBC + HMAC-SHA256 encryption matching Bitwarden's EncString format.

This module implements the cryptographic primitives used by Vaultwarden and
the Bitwarden protocol. All vault item fields are stored as EncStrings on the
server; this module handles deriving keys from a master password and
encrypting or decrypting those fields locally.

Typical usage example:

  master_key = derive_master_key(password, email)
  enc_key, mac_key = stretch_master_key(master_key)
  enc_string = encrypt_string("secret", enc_key, mac_key)
  plaintext = decrypt_string(enc_string, enc_key, mac_key)
"""

import base64
import hashlib
import hmac
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

_BACKEND = default_backend()

# AES block size in bits; required by the PKCS7 padder.
_AES_BLOCK_BITS = 128


def derive_master_key(
    password: str,
    email: str,
    iterations: int = 600_000,
) -> bytes:
    """Derives a 32-byte master key using PBKDF2-SHA256.

    Uses the same parameters as official Bitwarden clients. The email is
    normalised to lowercase and stripped of surrounding whitespace before
    use as the salt.

    Args:
        password: The user's master password.
        email: The account email address (used as the KDF salt).
        iterations: PBKDF2 iteration count. Defaults to 600,000.

    Returns:
        A 32-byte raw master key.
    """
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        email.strip().lower().encode("utf-8"),
        iterations,
    )


def stretch_master_key(master_key: bytes) -> tuple[bytes, bytes]:
    """Expands a master key into an encryption key and a MAC key.

    Uses HKDF-Expand (SHA-256) with info labels ``b"enc"`` and ``b"mac"``
    to derive two independent 32-byte keys.

    Args:
        master_key: A 32-byte master key, typically from
            :func:`derive_master_key`.

    Returns:
        A ``(enc_key, mac_key)`` tuple, each 32 bytes.
    """
    enc_key = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=32,
        info=b"enc",
        backend=_BACKEND,
    ).derive(master_key)
    mac_key = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=32,
        info=b"mac",
        backend=_BACKEND,
    ).derive(master_key)
    return enc_key, mac_key


def _verify_mac(
    mac_key: bytes,
    iv: bytes,
    ciphertext: bytes,
    mac: bytes,
) -> None:
    """Verifies the HMAC-SHA256 tag over IV + ciphertext.

    Args:
        mac_key: 32-byte MAC key.
        iv: Initialization vector used during encryption.
        ciphertext: Raw AES-256-CBC ciphertext bytes.
        mac: Expected HMAC-SHA256 digest to verify against.

    Raises:
        ValueError: If the computed MAC does not match ``mac``.
    """
    expected = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected):
        raise ValueError(
            "HMAC verification failed — wrong key or corrupted data."
        )


def decrypt_enc_string(
    enc_string: str,
    enc_key: bytes,
    mac_key: bytes,
) -> bytes:
    """Decrypts a Bitwarden EncString into raw bytes.

    Expects type-2 EncStrings, which encode AES-256-CBC ciphertext with an
    HMAC-SHA256 integrity tag in the format::

        2.<ciphertext_b64>|<iv_b64>|<mac_b64>

    Args:
        enc_string: A Bitwarden EncString beginning with ``"2."``.
        enc_key: 32-byte AES encryption key.
        mac_key: 32-byte HMAC key.

    Returns:
        The decrypted plaintext as raw bytes.

    Raises:
        ValueError: If the EncString format is invalid, the type is
            unsupported, or HMAC verification fails.
    """
    if "." not in enc_string:
        raise ValueError(f"Not a valid EncString: {enc_string[:20]!r}")

    prefix, rest = enc_string.split(".", 1)
    if prefix != "2":
        raise ValueError(
            f"Unsupported EncString type: {prefix!r}"
            " (only AES-256-CBC type 2 is supported)."
        )

    parts = rest.split("|")
    if len(parts) != 3:
        raise ValueError(
            f"Malformed EncString: expected 3 pipe-separated parts,"
            f" got {len(parts)}."
        )

    ciphertext = base64.b64decode(parts[0])
    iv = base64.b64decode(parts[1])
    mac = base64.b64decode(parts[2])

    _verify_mac(mac_key, iv, ciphertext, mac)

    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=_BACKEND)
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(_AES_BLOCK_BITS).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def decrypt_string(
    enc_string: str,
    enc_key: bytes,
    mac_key: bytes,
) -> str:
    """Decrypts a Bitwarden EncString into a UTF-8 string.

    Convenience wrapper around :func:`decrypt_enc_string`.

    Args:
        enc_string: A Bitwarden EncString beginning with ``"2."``.
        enc_key: 32-byte AES encryption key.
        mac_key: 32-byte HMAC key.

    Returns:
        The decrypted plaintext as a string.

    Raises:
        ValueError: If the EncString is invalid or HMAC verification fails.
        UnicodeDecodeError: If the decrypted bytes are not valid UTF-8.
    """
    return decrypt_enc_string(enc_string, enc_key, mac_key).decode("utf-8")


def encrypt_bytes(
    plaintext: bytes,
    enc_key: bytes,
    mac_key: bytes,
) -> str:
    """Encrypts raw bytes into Bitwarden EncString format.

    Generates a random 16-byte IV, applies PKCS7 padding, encrypts with
    AES-256-CBC, and appends an HMAC-SHA256 tag over the IV and ciphertext.

    Args:
        plaintext: Raw bytes to encrypt.
        enc_key: 32-byte AES encryption key.
        mac_key: 32-byte HMAC key.

    Returns:
        An EncString in the format ``2.<ct_b64>|<iv_b64>|<mac_b64>``.
    """
    iv = os.urandom(16)

    padder = padding.PKCS7(_AES_BLOCK_BITS).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=_BACKEND)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    mac = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()

    ct_b64 = base64.b64encode(ciphertext).decode()
    iv_b64 = base64.b64encode(iv).decode()
    mac_b64 = base64.b64encode(mac).decode()
    return f"2.{ct_b64}|{iv_b64}|{mac_b64}"


def encrypt_string(
    plaintext: str,
    enc_key: bytes,
    mac_key: bytes,
) -> str:
    """Encrypts a UTF-8 string into Bitwarden EncString format.

    Convenience wrapper around :func:`encrypt_bytes`.

    Args:
        plaintext: The string to encrypt.
        enc_key: 32-byte AES encryption key.
        mac_key: 32-byte HMAC key.

    Returns:
        An EncString in the format ``2.<ct_b64>|<iv_b64>|<mac_b64>``.
    """
    return encrypt_bytes(plaintext.encode("utf-8"), enc_key, mac_key)


def decrypt_profile_key(
    profile_key_enc: str,
    stretched_enc: bytes,
    stretched_mac: bytes,
) -> tuple[bytes, bytes]:
    """Decrypts the vault profile's symmetric key.

    The Vaultwarden server stores the user's 64-byte symmetric key as an
    EncString encrypted with the stretched master key. This function
    decrypts that blob and splits it into the AES encryption key (first
    32 bytes) and the HMAC key (last 32 bytes) used for all vault items.

    Args:
        profile_key_enc: The EncString from ``GET /api/sync``
            ``Profile.Key``.
        stretched_enc: 32-byte AES key derived from
            :func:`stretch_master_key`.
        stretched_mac: 32-byte HMAC key derived from
            :func:`stretch_master_key`.

    Returns:
        A ``(enc_key, mac_key)`` tuple for encrypting and decrypting
        vault item fields.

    Raises:
        ValueError: If decryption fails or the decrypted blob is not
            exactly 64 bytes.
    """
    raw = decrypt_enc_string(profile_key_enc, stretched_enc, stretched_mac)
    if len(raw) != 64:
        raise ValueError(
            f"Expected 64-byte symmetric key after decryption,"
            f" got {len(raw)} bytes."
        )
    return raw[:32], raw[32:]
