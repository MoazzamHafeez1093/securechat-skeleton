"""Helper signatures: now_ms, b64e, b64d, sha256_hex."""
import base64
import hashlib
import time
from typing import Union


def now_ms() -> int:
    """Return current Unix timestamp in milliseconds."""
    return int(time.time() * 1000)


def b64e(b: bytes) -> str:
    """Base64 encode bytes to string."""
    return base64.b64encode(b).decode('ascii')


def b64d(s: str) -> bytes:
    """Base64 decode string to bytes."""
    return base64.b64decode(s)


def sha256_hex(data: Union[bytes, str]) -> str:
    """Compute SHA-256 hash and return as hex string."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def sha256_digest(data: Union[bytes, str]) -> bytes:
    """Compute SHA-256 hash and return as bytes."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).digest()


def bytes_to_int(b: bytes) -> int:
    """Convert bytes to integer (big-endian)."""
    return int.from_bytes(b, byteorder='big')


def int_to_bytes(n: int, length: int = None) -> bytes:
    """Convert integer to bytes (big-endian)."""
    if length is None:
        length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, byteorder='big')


def compute_cert_fingerprint(cert) -> str:
    """
    Compute SHA-256 fingerprint of X.509 certificate.
    
    Args:
        cert: cryptography Certificate object
        
    Returns:
        Hex-encoded SHA-256 hash of DER-encoded certificate
    """
    from cryptography.hazmat.primitives import serialization
    cert_bytes = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(cert_bytes).hexdigest()
