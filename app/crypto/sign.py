"""RSA PKCS#1 v1.5 SHA-256 sign/verify."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature
from typing import Union


def rsa_sign(data: Union[bytes, str], private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Sign data using RSA with PKCS#1 v1.5 padding and SHA-256.
    
    Per assignment Section 2.4:
    - Compute h = SHA256(seqno||timestamp||ciphertext)
    - Sign: sig = RSA_SIGN(h)
    
    Per assignment Section 2.5:
    - Sign transcript hash: sig = RSA_SIGN(transcript_sha256)
    
    Args:
        data: data to sign (bytes or string)
        private_key: RSA private key
        
    Returns:
        RSA signature bytes
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    return signature


def rsa_verify(data: Union[bytes, str], signature: bytes, public_key: rsa.RSAPublicKey) -> bool:
    """
    Verify RSA signature using PKCS#1 v1.5 padding and SHA-256.
    
    Per assignment Section 2.4:
    - Recompute h = SHA256(seqno||timestamp||ciphertext)
    - Verify signature using sender's certificate
    
    Args:
        data: original data that was signed
        signature: RSA signature to verify
        public_key: RSA public key (from sender's certificate)
        
    Returns:
        True if signature is valid, False otherwise
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def compute_message_hash(seqno: int, timestamp: int, ciphertext: bytes) -> bytes:
    """
    Compute message hash for signing/verification.
    
    Per assignment Section 2.4:
    h = SHA256(seqno||timestamp||ciphertext)
    
    Args:
        seqno: sequence number
        timestamp: Unix timestamp in milliseconds
        ciphertext: encrypted message bytes
        
    Returns:
        SHA-256 hash bytes (32 bytes)
    """
    import hashlib
    
    # Format: "seqno||timestamp||" + ciphertext bytes
    hash_input = f"{seqno}||{timestamp}||".encode('utf-8') + ciphertext
    
    return hashlib.sha256(hash_input).digest()
