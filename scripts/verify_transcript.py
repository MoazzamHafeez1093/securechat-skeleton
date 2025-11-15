"""
Offline verification of transcript and SessionReceipt.
Demonstrates non-repudiation per assignment requirements.
"""

import json
import base64
import hashlib
import sys
import os
import shutil
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


def load_certificate(cert_path: str) -> x509.Certificate:
    """Load certificate from PEM file."""
    with open(cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())


def verify_transcript_and_receipt(
    transcript_file: str, 
    receipt_file: str, 
    cert_path: str
) -> bool:
    """
    Verify non-repudiation:
    1. Each message signature in transcript
    2. SessionReceipt signature
    3. Transcript integrity
    
    Returns:
        True if all verifications pass, False otherwise
    """
    print(f"\n[*] Verifying: {transcript_file}")
    print(f"[*] Receipt: {receipt_file}")
    print(f"[*] Certificate: {cert_path}")
    print("=" * 60)
    
    # Load certificate
    try:
        cert = load_certificate(cert_path)
        public_key = cert.public_key()
        print(f"[✓] Certificate loaded")
    except Exception as e:
        print(f"[✗] Failed to load certificate: {e}")
        return False
    
    # Read transcript
    try:
        with open(transcript_file, "r") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"[✗] Transcript file not found: {transcript_file}")
        return False
    
    print(f"\n[*] Verifying {len(lines)} messages in transcript...")
    
    # Verify each message signature
    verified_count = 0
    for i, line in enumerate(lines, 1):
        try:
            parts = line.strip().split('|')
            if len(parts) != 5:
                print(f"  [✗] Message {i}: Invalid format (expected 5 fields, got {len(parts)})")
                return False
            
            seqno = int(parts[0])
            ts = int(parts[1])
            ct = base64.b64decode(parts[2])
            sig = base64.b64decode(parts[3])
            fingerprint = parts[4]
            
            # Recompute hash: SHA256(seqno || ts || ct)
            hash_input = f"{seqno}||{ts}||".encode() + ct
            computed_hash = hashlib.sha256(hash_input).digest()
            
            # Verify RSA signature
            try:
                public_key.verify(
                    sig,
                    computed_hash,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                print(f"  [✓] Message {i} (seqno={seqno}): Signature valid")
                verified_count += 1
            except InvalidSignature:
                print(f"  [✗] Message {i} (seqno={seqno}): Signature INVALID (SIG_FAIL)")
                return False
        except Exception as e:
            print(f"  [✗] Message {i}: Verification error - {e}")
            return False
    
    print(f"\n[✓] All {verified_count} message signatures verified")
    
    # Load SessionReceipt
    try:
        with open(receipt_file, "r") as f:
            receipt = json.load(f)
    except FileNotFoundError:
        print(f"[✗] Receipt file not found: {receipt_file}")
        return False
    except json.JSONDecodeError as e:
        print(f"[✗] Invalid receipt JSON: {e}")
        return False
    
    print(f"\n[*] Verifying SessionReceipt...")
    print(f"  Peer: {receipt['peer']}")
    print(f"  First seq: {receipt['first_seq']}")
    print(f"  Last seq: {receipt['last_seq']}")
    print(f"  Transcript SHA256: {receipt['transcript_sha256']}")
    
    # Recompute transcript hash
    full_transcript = "".join(lines)
    computed_transcript_hash = hashlib.sha256(full_transcript.encode()).hexdigest()
    
    if computed_transcript_hash != receipt['transcript_sha256']:
        print(f"  [✗] Transcript hash mismatch!")
        print(f"      Expected: {receipt['transcript_sha256']}")
        print(f"      Got:      {computed_transcript_hash}")
        return False
    
    print(f"  [✓] Transcript hash matches")
    
    # Verify receipt signature (signature over transcript hash)
    try:
        receipt_sig = base64.b64decode(receipt['sig'])
        public_key.verify(
            receipt_sig,
            bytes.fromhex(receipt['transcript_sha256']),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print(f"  [✓] Receipt signature valid")
    except InvalidSignature:
        print(f"  [✗] Receipt signature INVALID")
        return False
    except Exception as e:
        print(f"  [✗] Receipt verification error: {e}")
        return False
    
    print("\n" + "=" * 60)
    print("[✓] VERIFICATION SUCCESSFUL - Non-repudiation proven!")
    print("=" * 60)
    return True


def tamper_test(transcript_file: str) -> bool:
    """Test that tampering breaks verification."""
    print(f"\n[*] Testing tampering detection...")
    
    # Make a backup
    backup_file = transcript_file + ".backup"
    try:
        shutil.copy(transcript_file, backup_file)
    except Exception as e:
        print(f"[✗] Failed to create backup: {e}")
        return False
    
    # Tamper with transcript
    try:
        with open(transcript_file, "r") as f:
            lines = f.readlines()
        
        if not lines:
            print(f"[✗] Transcript is empty, cannot tamper")
            return False
        
        # Modify first character of first line
        lines[0] = 'X' + lines[0][1:]
        
        with open(transcript_file, "w") as f:
            f.writelines(lines)
        
        print(f"[*] Tampered with transcript (modified 1 character)")
        return True
    except Exception as e:
        print(f"[✗] Failed to tamper: {e}")
        return False


def restore_backup(transcript_file: str) -> bool:
    """Restore transcript from backup."""
    backup_file = transcript_file + ".backup"
    try:
        shutil.copy(backup_file, transcript_file)
        os.remove(backup_file)
        print(f"\n[*] Restored original transcript from backup")
        return True
    except Exception as e:
        print(f"[✗] Failed to restore backup: {e}")
        return False


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python verify_transcript.py <transcript_file> <receipt_file> <cert_file>")
        print("\nExample:")
        print("  python scripts/verify_transcript.py \\")
        print("    transcripts/client_session_1234567890.txt \\")
        print("    transcripts/client_session_1234567890_receipt.json \\")
        print("    certs/client_cert.pem")
        sys.exit(1)
    
    transcript_file = sys.argv[1]
    receipt_file = sys.argv[2]
    cert_file = sys.argv[3]
    
    # Verify original
    result = verify_transcript_and_receipt(transcript_file, receipt_file, cert_file)
    
    if result:
        # Offer tampering test
        try:
            choice = input("\n[?] Test tampering detection? (y/n): ")
            if choice.lower() == 'y':
                if tamper_test(transcript_file):
                    print("\n[*] Verifying tampered transcript...")
                    verify_transcript_and_receipt(transcript_file, receipt_file, cert_file)
                    
                    # Restore backup
                    restore_backup(transcript_file)
        except KeyboardInterrupt:
            print("\n[*] Interrupted")
            sys.exit(0)
    else:
        print("\n[✗] Verification failed!")
        sys.exit(1)