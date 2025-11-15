"""Classic DH helpers + Trunc16(SHA256(Ks)) derivation."""
import secrets
import hashlib
from typing import Tuple
from ..common.utils import int_to_bytes

# Safe prime from RFC 3526 (2048-bit MODP Group)
DEFAULT_DH_PRIME = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
DEFAULT_DH_GENERATOR = 2


def generate_dh_keypair(p: int = None, g: int = None) -> Tuple[int, int, int, int]:
    """
    Generate Diffie-Hellman keypair.
    
    Per assignment: Each side chooses a private key (a or b) and computes A = g^a mod p.
    
    Args:
        p: prime modulus (default: RFC 3526 2048-bit prime)
        g: generator (default: 2)
        
    Returns:
        Tuple of (p, g, private_key, public_key)
        - p: prime modulus
        - g: generator
        - private_key: random private exponent (a or b)
        - public_key: g^private_key mod p (A or B)
    """
    if p is None:
        p = DEFAULT_DH_PRIME
    if g is None:
        g = DEFAULT_DH_GENERATOR
    
    # Generate random private key in range [2, p-2]
    private_key = secrets.randbelow(p - 3) + 2
    
    # Compute public key: A = g^a mod p (or B = g^b mod p)
    public_key = pow(g, private_key, p)
    
    return p, g, private_key, public_key


def compute_shared_secret(peer_public_key: int, own_private_key: int, p: int) -> int:
    """
    Compute DH shared secret.
    
    Per assignment Section 2.3:
    - Client computes: Ks = B^a mod p
    - Server computes: Ks = A^b mod p
    
    Args:
        peer_public_key: other party's public key (B for client, A for server)
        own_private_key: own private key (a for client, b for server)
        p: prime modulus
        
    Returns:
        Shared secret Ks (integer)
    """
    return pow(peer_public_key, own_private_key, p)


def derive_aes_key_from_dh(shared_secret: int) -> bytes:
    """
    Derive AES-128 key from DH shared secret.
    
    Per assignment Section 2.2 and 2.3:
    K = Trunc16(SHA256(big-endian(Ks)))
    
    This is used for:
    - Temporary key for registration/login credential encryption
    - Session key for chat message encryption
    
    Args:
        shared_secret: DH shared secret Ks (integer)
        
    Returns:
        16-byte AES-128 key
    """
    # Convert shared secret to big-endian bytes
    ks_bytes = int_to_bytes(shared_secret)
    
    # Hash with SHA-256
    hash_digest = hashlib.sha256(ks_bytes).digest()
    
    # Truncate to 16 bytes for AES-128
    aes_key = hash_digest[:16]
    
    return aes_key


def get_default_dh_params() -> Tuple[int, int]:
    """
    Get default DH parameters (safe prime from RFC 3526).
    
    Returns:
        Tuple of (p, g)
    """
    return DEFAULT_DH_PRIME, DEFAULT_DH_GENERATOR
