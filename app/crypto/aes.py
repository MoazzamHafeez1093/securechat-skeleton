"""AES-128 CBC + PKCS#7 helpers (use cryptography library)."""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
from typing import Tuple


def aes_encrypt(plaintext: str, key: bytes) -> bytes:
    """
    Encrypt plaintext using AES-128 in CBC mode with PKCS#7 padding.
    
    Args:
        plaintext: plaintext string to encrypt
        key: 16-byte AES key
        
    Returns:
        IV + ciphertext (concatenated bytes)
        
    Raises:
        ValueError: if key length is not 16 bytes
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires 16-byte key")
    
    # Generate random IV (16 bytes for AES)
    iv = os.urandom(16)
    
    # Apply PKCS#7 padding
    padder = padding.PKCS7(128).padder()  # 128 bits = 16 bytes block size
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    
    # Encrypt using AES-128-CBC
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # Prepend IV to ciphertext for transmission
    return iv + ciphertext


def aes_decrypt(ciphertext: bytes, key: bytes) -> str:
    """
    Decrypt ciphertext using AES-128 in CBC mode.
    
    Args:
        ciphertext: IV + encrypted data (IV is first 16 bytes)
        key: 16-byte AES key
        
    Returns:
        Decrypted plaintext string
        
    Raises:
        ValueError: if key length is not 16 bytes or ciphertext too short
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires 16-byte key")
    
    if len(ciphertext) < 16:
        raise ValueError("Ciphertext too short (must include IV)")
    
    # Extract IV from first 16 bytes
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    
    # Decrypt using AES-128-CBC
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ct) + decryptor.finalize()
    
    # Remove PKCS#7 padding
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plaintext.decode('utf-8')


def derive_aes_key_from_dh(shared_secret: int) -> bytes:
    """
    Derive AES-128 key from Diffie-Hellman shared secret.
    
    As per assignment spec:
    K = Trunc16(SHA256(big-endian(Ks)))
    
    Args:
        shared_secret: DH shared secret (integer)
        
    Returns:
        16-byte AES key
    """
    import hashlib
    from ..common.utils import int_to_bytes
    
    # Convert shared secret to big-endian bytes
    ks_bytes = int_to_bytes(shared_secret)
    
    # Hash and truncate to 16 bytes
    hash_digest = hashlib.sha256(ks_bytes).digest()
    aes_key = hash_digest[:16]  # Truncate to 128 bits
    
    return aes_key
