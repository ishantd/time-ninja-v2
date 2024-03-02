from base64 import b64decode, b64encode
from hashlib import sha256
from typing import Optional

import fastapi.logger as logger
from Crypto.Cipher import AES

from app.settings import settings


def get_aes_key() -> bytes:
    """Get the AES key from settings.token_secret."""
    return sha256(settings.token_secret.encode()).digest()


def encrypt(data: str) -> str:
    """Encrypt data."""
    key = get_aes_key()
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data.encode("utf-8"))
    return b64encode(nonce + tag + ciphertext).decode("utf-8")


def decrypt(data: str) -> Optional[str]:
    """Decrypt data."""
    key = get_aes_key()
    try:
        data = b64decode(data)
        nonce = data[:16]
        tag = data[16:32]
        ciphertext = data[32:]
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode("utf-8")
    except Exception as e:
        logger.error(f"Error decrypting data: {e}")
        return None


def string_to_bytes(data: str) -> bytes:
    """Convert string to bytes."""
    return data.encode("utf-8")


def bytes_to_string(data: bytes) -> str:
    """Convert bytes to string."""
    return data.decode("utf-8")
