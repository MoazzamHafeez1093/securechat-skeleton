"""Test transcript and verification functionality."""
import sys
sys.path.insert(0, 'd:/infosec_assignment2/securechat-skeleton')

from app.storage.transcript import Transcript
from app.crypto.pki import load_certificate, load_private_key
from app.common.utils import compute_cert_fingerprint
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os
import tempfile
import shutil

print("Testing Transcript and Non-Repudiation")
print("=" * 60)

# Create temporary directory for test files
test_dir = tempfile.mkdtemp()
transcript_path = os.path.join(test_dir, "test_transcript.txt")
receipt_path = os.path.join(test_dir, "test_receipt.json")

try:
    print("\n1. Creating test transcript:")
    transcript = Transcript(transcript_path)
    print(f"   ✓ Transcript file created: {transcript_path}")
    
    print("\n2. Loading certificates and keys:")
    certs_dir = "d:/infosec_assignment2/securechat-skeleton/certs"
    client_cert = load_certificate(os.path.join(certs_dir, "client_cert.pem"))
    client_key = load_private_key(os.path.join(certs_dir, "client_key.pem"))
    client_fingerprint = compute_cert_fingerprint(client_cert)
    print(f"   ✓ Client cert loaded")
    print(f"   ✓ Client fingerprint: {client_fingerprint[:16]}...")
    
    print("\n3. Appending test messages to transcript:")
    # Simulate 3 messages
    for i in range(1, 4):
        seqno = i
        timestamp = 1700000000000 + (i * 1000)
        ciphertext = f"encrypted_message_{i}".encode()
        
        # Compute hash and sign
        hash_input = f"{seqno}||{timestamp}||".encode() + ciphertext
        message_hash = hashes.Hash(hashes.SHA256())
        message_hash.update(hash_input)
        digest = message_hash.finalize()
        
        signature = client_key.sign(
            digest,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        # Append to transcript
        transcript.append_message(
            seqno=seqno,
            timestamp=timestamp,
            ciphertext=ciphertext,
            signature=signature,
            peer_cert_fingerprint=client_fingerprint
        )
        print(f"   ✓ Message {i} appended (seqno={seqno})")
    
    print("\n4. Computing transcript hash:")
    transcript_hash = transcript.compute_transcript_hash()
    print(f"   ✓ Transcript SHA-256: {transcript_hash}")
    
    print("\n5. Generating SessionReceipt:")
    # Sign transcript hash
    receipt_signature = client_key.sign(
        bytes.fromhex(transcript_hash),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    receipt = transcript.generate_session_receipt(
        peer="client",
        signature=receipt_signature
    )
    print(f"   ✓ Receipt generated:")
    print(f"     - Peer: {receipt['peer']}")
    print(f"     - First seq: {receipt['first_seq']}")
    print(f"     - Last seq: {receipt['last_seq']}")
    print(f"     - Hash: {receipt['transcript_sha256'][:32]}...")
    
    print("\n6. Saving receipt to file:")
    transcript.save_receipt(receipt, receipt_path)
    print(f"   ✓ Receipt saved: {receipt_path}")
    
    print("\n7. Verifying message count:")
    msg_count = transcript.get_message_count()
    print(f"   ✓ Total messages: {msg_count}")
    
    print("\n" + "=" * 60)
    print("✓ Transcript tests completed!")
    print("\nFiles created for verification testing:")
    print(f"  - Transcript: {transcript_path}")
    print(f"  - Receipt: {receipt_path}")
    print(f"  - Cert: {os.path.join(certs_dir, 'client_cert.pem')}")
    
    print("\nYou can now test offline verification with:")
    print(f"  python scripts/verify_transcript.py \\")
    print(f"    {transcript_path} \\")
    print(f"    {receipt_path} \\")
    print(f"    {os.path.join(certs_dir, 'client_cert.pem')}")
    
    # Keep temp directory for manual testing
    print(f"\n[*] Test files saved in: {test_dir}")
    print("[*] (Directory will be kept for manual verification)")

except Exception as e:
    print(f"\n✗ Test failed: {e}")
    import traceback
    traceback.print_exc()
    shutil.rmtree(test_dir, ignore_errors=True)
