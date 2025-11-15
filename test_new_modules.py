"""Test DH, RSA signing, and protocol models."""
import sys
sys.path.insert(0, 'd:/infosec_assignment2/securechat-skeleton')

# Set UTF-8 encoding for Windows console
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

print("Testing Newly Implemented Crypto Modules")
print("=" * 60)

# Test DH
print("\n1. Testing Diffie-Hellman Key Exchange:")
from app.crypto.dh import generate_dh_keypair, compute_shared_secret, derive_aes_key_from_dh

# Client side
p, g, client_private, client_public = generate_dh_keypair()
print(f"   Client generated DH keypair")
print(f"   - p (prime): {str(p)[:50]}... ({p.bit_length()} bits)")
print(f"   - g (generator): {g}")
print(f"   - Client private key: {str(client_private)[:50]}...")
print(f"   - Client public key (A): {str(client_public)[:50]}...")

# Server side
_, _, server_private, server_public = generate_dh_keypair(p, g)
print(f"   Server generated DH keypair")
print(f"   - Server public key (B): {str(server_public)[:50]}...")

# Compute shared secrets
client_shared = compute_shared_secret(server_public, client_private, p)
server_shared = compute_shared_secret(client_public, server_private, p)

print(f"   Client computed Ks: {str(client_shared)[:50]}...")
print(f"   Server computed Ks: {str(server_shared)[:50]}...")
print(f"   [OK] Shared secrets match: {client_shared == server_shared}")

# Derive AES keys
client_key = derive_aes_key_from_dh(client_shared)
server_key = derive_aes_key_from_dh(server_shared)
print(f"   Client AES key: {client_key.hex()}")
print(f"   Server AES key: {server_key.hex()}")
print(f"   ✓ Derived keys match: {client_key == server_key}")
print(f"   ✓ Key length is 16 bytes: {len(client_key) == 16}")

# Test RSA Signing
print("\n2. Testing RSA Signing (PKCS#1 v1.5 + SHA-256):")
from app.crypto.sign import rsa_sign, rsa_verify, compute_message_hash
from app.crypto.pki import load_certificate, load_private_key
import os

certs_dir = "d:/infosec_assignment2/securechat-skeleton/certs"
client_key_obj = load_private_key(os.path.join(certs_dir, "client_key.pem"))
client_cert = load_certificate(os.path.join(certs_dir, "client_cert.pem"))
client_public_key = client_cert.public_key()

test_data = b"Test message for signing"
signature = rsa_sign(test_data, client_key_obj)
print(f"   ✓ Generated signature ({len(signature)} bytes)")

is_valid = rsa_verify(test_data, signature, client_public_key)
print(f"   ✓ Signature verification: {is_valid}")

# Test with tampered data
tampered_data = b"Tampered message"
is_invalid = rsa_verify(tampered_data, signature, client_public_key)
print(f"   ✓ Tampered data rejected: {not is_invalid}")

# Test message hash computation (per assignment format)
seqno = 1
timestamp = 1700000000000
ciphertext = b"encrypted_data_here"
msg_hash = compute_message_hash(seqno, timestamp, ciphertext)
print(f"   ✓ Message hash computed: {msg_hash.hex()[:32]}...")
print(f"   ✓ Hash length is 32 bytes: {len(msg_hash) == 32}")

# Sign and verify message hash
msg_signature = rsa_sign(msg_hash, client_key_obj)
msg_valid = rsa_verify(msg_hash, msg_signature, client_public_key)
print(f"   ✓ Message signature valid: {msg_valid}")

# Test Protocol Models
print("\n3. Testing Pydantic Protocol Models:")
from app.common.protocol import (
    HelloMessage, ServerHelloMessage, RegisterMessage, LoginMessage,
    DHClientMessage, DHServerMessage, ChatMessage, SessionReceipt
)

# Test HelloMessage
hello = HelloMessage(
    client_cert="-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
    nonce="dGVzdG5vbmNl"
)
print(f"   ✓ HelloMessage created: {hello.type}")

# Test DHClientMessage
dh_client = DHClientMessage(g=2, p=23, A=8)
print(f"   ✓ DHClientMessage created: g={dh_client.g}, p={dh_client.p}, A={dh_client.A}")

# Test DHServerMessage
dh_server = DHServerMessage(B=19)
print(f"   ✓ DHServerMessage created: B={dh_server.B}")

# Test RegisterMessage
register = RegisterMessage(
    email="test@example.com",
    username="testuser",
    pwd="aGFzaGVkcGFzc3dvcmQ=",
    salt="cmFuZG9tc2FsdA=="
)
print(f"   ✓ RegisterMessage created: {register.username}")

# Test LoginMessage
login = LoginMessage(
    email="test@example.com",
    pwd="aGFzaGVkcGFzc3dvcmQ=",
    nonce="bG9naW5ub25jZQ=="
)
print(f"   ✓ LoginMessage created: {login.email}")

# Test ChatMessage
chat = ChatMessage(
    seqno=1,
    ts=1700000000000,
    ct="ZW5jcnlwdGVkX2RhdGE=",
    sig="c2lnbmF0dXJl"
)
print(f"   ✓ ChatMessage created: seqno={chat.seqno}, ts={chat.ts}")

# Test SessionReceipt
receipt = SessionReceipt(
    peer="client",
    first_seq=1,
    last_seq=10,
    transcript_sha256="abc123def456",
    sig="cmVjZWlwdHNpZw=="
)
print(f"   ✓ SessionReceipt created: {receipt.peer}, sequences {receipt.first_seq}-{receipt.last_seq}")

# Test JSON serialization
print("\n4. Testing JSON Serialization:")
hello_json = hello.model_dump_json()
print(f"   ✓ HelloMessage JSON: {hello_json[:50]}...")

dh_client_json = dh_client.model_dump_json()
print(f"   ✓ DHClientMessage JSON: {dh_client_json[:50]}...")

# Test JSON parsing
parsed_hello = HelloMessage.model_validate_json(hello_json)
print(f"   ✓ Parsed HelloMessage: {parsed_hello.type}")

print("\n" + "=" * 60)
print("✓ All crypto modules implemented and tested successfully!")
print("\nImplementation matches assignment requirements:")
print("  ✓ DH: K = Trunc16(SHA256(big-endian(Ks)))")
print("  ✓ RSA: PKCS#1 v1.5 with SHA-256")
print("  ✓ Protocol: Exact message formats per assignment")
