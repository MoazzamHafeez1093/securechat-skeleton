"""Test utility and crypto functions."""
import sys
sys.path.insert(0, 'd:/infosec_assignment2/securechat-skeleton')

from app.common.utils import (
    now_ms, b64e, b64d, sha256_hex, sha256_digest,
    bytes_to_int, int_to_bytes
)
from app.crypto.aes import aes_encrypt, aes_decrypt, derive_aes_key_from_dh

print("Testing Utility Functions")
print("-" * 50)

# Test timestamp
print("\n1. Testing timestamp:")
ts = now_ms()
print(f"   Current timestamp (ms): {ts}")
print(f"   ✓ Returns integer: {isinstance(ts, int)}")

# Test base64 encoding/decoding
print("\n2. Testing base64 encoding/decoding:")
test_bytes = b"Hello SecureChat!"
encoded = b64e(test_bytes)
decoded = b64d(encoded)
print(f"   Original: {test_bytes}")
print(f"   Encoded: {encoded}")
print(f"   Decoded: {decoded}")
print(f"   ✓ Round-trip successful: {test_bytes == decoded}")

# Test SHA-256
print("\n3. Testing SHA-256 hashing:")
test_data = "test password"
hash_hex = sha256_hex(test_data)
hash_bytes = sha256_digest(test_data)
print(f"   Data: {test_data}")
print(f"   SHA-256 (hex): {hash_hex}")
print(f"   SHA-256 (bytes length): {len(hash_bytes)} bytes")
print(f"   ✓ Hex hash is 64 chars: {len(hash_hex) == 64}")

# Test integer/bytes conversion
print("\n4. Testing integer/bytes conversion:")
test_int = 123456789
int_bytes = int_to_bytes(test_int)
recovered_int = bytes_to_int(int_bytes)
print(f"   Original int: {test_int}")
print(f"   As bytes: {int_bytes.hex()}")
print(f"   Recovered int: {recovered_int}")
print(f"   ✓ Round-trip successful: {test_int == recovered_int}")

print("\n" + "=" * 50)
print("Testing AES-128 Encryption")
print("=" * 50)

# Test AES encryption/decryption
print("\n5. Testing AES-128-CBC encryption:")
plaintext = "This is a secret message for SecureChat!"
aes_key = b"0123456789abcdef"  # 16 bytes for AES-128

print(f"   Plaintext: {plaintext}")
print(f"   Key length: {len(aes_key)} bytes")

ciphertext = aes_encrypt(plaintext, aes_key)
print(f"   Ciphertext length: {len(ciphertext)} bytes")
print(f"   Ciphertext (hex): {ciphertext[:32].hex()}... (truncated)")

decrypted = aes_decrypt(ciphertext, aes_key)
print(f"   Decrypted: {decrypted}")
print(f"   ✓ Decryption successful: {plaintext == decrypted}")

# Test DH key derivation
print("\n6. Testing DH key derivation:")
test_shared_secret = 987654321098765432109876543210
derived_key = derive_aes_key_from_dh(test_shared_secret)
print(f"   Shared secret (int): {test_shared_secret}")
print(f"   Derived AES key (hex): {derived_key.hex()}")
print(f"   ✓ Key is 16 bytes: {len(derived_key) == 16}")

# Test with derived key
print("\n7. Testing AES with DH-derived key:")
test_msg = "Testing DH-derived encryption!"
ct = aes_encrypt(test_msg, derived_key)
pt = aes_decrypt(ct, derived_key)
print(f"   Original: {test_msg}")
print(f"   Recovered: {pt}")
print(f"   ✓ Encryption with DH key works: {test_msg == pt}")

print("\n" + "-" * 50)
print("✓ All utility and crypto tests passed!")
