#!/usr/bin/env python3
"""
Offline Transcript Verification Script

Per Assignment Section 3 (Testing & Evidence):
- Verify each message: recompute SHA-256 digest; verify RSA signature
- Verify receipt: verify RSA signature over TranscriptHash
- Show that any edit breaks verification

Usage:
    python scripts/verify_transcript.py

This script demonstrates non-repudiation by independently verifying:
1. Each message signature (RSA PKCS#1 v1.5 with SHA-256)
2. Transcript integrity (SHA-256 hash)
3. SessionReceipt signature (proving authenticity)
"""

import sys
import os
import hashlib
import base64
import json
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from app.crypto.sign import rsa_verify
from app.common.utils import b64d


def load_transcript(filepath):
    """
    Load transcript file and parse entries.
    
    Format: seqno|timestamp|ciphertext_b64|signature_b64|peer_cert_fingerprint
    
    Returns:
        List of tuples: (seqno, ts, ct_bytes, sig_bytes, fingerprint)
    """
    messages = []
    
    with open(filepath, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            
            try:
                parts = line.split('|')
                if len(parts) != 5:
                    print(f"[!] Warning: Line {line_num} has {len(parts)} fields (expected 5)")
                    continue
                
                seqno = int(parts[0])
                ts = int(parts[1])
                ct = base64.b64decode(parts[2])
                sig = base64.b64decode(parts[3])
                fingerprint = parts[4]
                
                messages.append((seqno, ts, ct, sig, fingerprint))
            except Exception as e:
                print(f"[!] Error parsing line {line_num}: {e}")
                continue
    
    return messages


def load_receipt(filepath):
    """
    Load SessionReceipt JSON file.
    
    Returns:
        Dict with: type, peer, first_seq, last_seq, transcript_sha256, sig
    """
    with open(filepath, 'r', encoding='utf-8') as f:
        receipt = json.load(f)
    
    return receipt


def load_certificate(filepath):
    """Load X.509 certificate from PEM file."""
    with open(filepath, 'rb') as f:
        cert_data = f.read()
    
    return x509.load_pem_x509_certificate(cert_data)


def compute_message_hash(seqno, timestamp, ciphertext):
    """
    Compute message hash for signature verification.
    
    Per assignment: h = SHA256(seqno||timestamp||ciphertext)
    """
    hash_input = f"{seqno}||{timestamp}||".encode('utf-8') + ciphertext
    return hashlib.sha256(hash_input).digest()


def compute_transcript_hash(filepath):
    """
    Compute SHA-256 hash of entire transcript file.
    
    Returns:
        Hex-encoded SHA-256 hash
    """
    with open(filepath, 'rb') as f:
        transcript_bytes = f.read()
    
    return hashlib.sha256(transcript_bytes).hexdigest()


def verify_message_signatures(messages, peer_cert):
    """
    Verify RSA signature for each message.
    
    Args:
        messages: List of (seqno, ts, ct, sig, fingerprint) tuples
        peer_cert: X.509 certificate of message sender
        
    Returns:
        (success_count, total_count)
    """
    peer_public_key = peer_cert.public_key()
    success_count = 0
    
    print("\n=== Verifying Individual Message Signatures ===")
    
    for seqno, ts, ct, sig, fingerprint in messages:
        # Recompute message hash
        h = compute_message_hash(seqno, ts, ct)
        
        # Verify signature
        is_valid = rsa_verify(h, sig, peer_public_key)
        
        if is_valid:
            print(f"[OK] Message {seqno} (seqno={seqno}): Signature valid ✓")
            success_count += 1
        else:
            print(f"[FAIL] Message {seqno} (seqno={seqno}): Signature INVALID ✗")
    
    return success_count, len(messages)


def verify_transcript_integrity(transcript_path, receipt):
    """
    Verify transcript hash matches SessionReceipt.
    
    Returns:
        True if hash matches, False otherwise
    """
    print("\n=== Verifying Transcript Integrity ===")
    
    # Compute hash of transcript file
    computed_hash = compute_transcript_hash(transcript_path)
    expected_hash = receipt['transcript_sha256']
    
    print(f"[*] Expected hash: {expected_hash}")
    print(f"[*] Computed hash: {computed_hash}")
    
    if computed_hash == expected_hash:
        print("[OK] Transcript hash matches! ✓")
        return True
    else:
        print("[FAIL] Transcript hash MISMATCH! ✗")
        print("     → Transcript has been tampered with!")
        return False


def verify_receipt_signature(receipt, peer_cert):
    """
    Verify SessionReceipt signature.
    
    Receipt signature is over the transcript SHA-256 hash (as bytes, not hex string).
    
    Returns:
        True if signature valid, False otherwise
    """
    print("\n=== Verifying SessionReceipt Signature ===")
    
    transcript_hash = receipt['transcript_sha256']
    receipt_sig = base64.b64decode(receipt['sig'])
    peer_public_key = peer_cert.public_key()
    
    # Verify signature over transcript hash (convert hex string to bytes)
    is_valid = rsa_verify(bytes.fromhex(transcript_hash), receipt_sig, peer_public_key)
    
    if is_valid:
        print("[OK] SessionReceipt signature valid ✓")
        print("     → Receipt is authentic and unmodified")
        return True
    else:
        print("[FAIL] SessionReceipt signature INVALID ✗")
        print("     → Receipt may have been tampered with!")
        return False


def print_summary(sig_success, sig_total, hash_valid, receipt_valid):
    """Print final verification summary."""
    print("\n" + "="*60)
    print("VERIFICATION SUMMARY")
    print("="*60)
    
    print(f"\nMessage Signatures: {sig_success}/{sig_total} valid")
    print(f"Transcript Hash:    {'MATCH ✓' if hash_valid else 'MISMATCH ✗'}")
    print(f"Receipt Signature:  {'VALID ✓' if receipt_valid else 'INVALID ✗'}")
    
    if sig_success == sig_total and hash_valid and receipt_valid:
        print("\n" + "="*60)
        print("✓ VERIFICATION PASSED")
        print("="*60)
        print("\nConclusion:")
        print("  • All message signatures are authentic")
        print("  • Transcript has not been modified")
        print("  • SessionReceipt is valid")
        print("  • Non-repudiation: Sender cannot deny these messages")
        return True
    else:
        print("\n" + "="*60)
        print("✗ VERIFICATION FAILED")
        print("="*60)
        print("\nIssues detected:")
        if sig_success < sig_total:
            print(f"  • {sig_total - sig_success} message(s) have invalid signatures")
        if not hash_valid:
            print("  • Transcript has been tampered with (hash mismatch)")
        if not receipt_valid:
            print("  • Receipt signature is invalid")
        return False


def main():
    """Main verification workflow."""
    print("="*60)
    print("SECURECHAT - OFFLINE TRANSCRIPT VERIFICATION")
    print("="*60)
    print("\nThis tool verifies the authenticity and integrity of")
    print("SecureChat session transcripts using digital signatures.")
    print()
    
    # Get file paths from user
    try:
        transcript_path = input("Enter transcript file path: ").strip()
        if not os.path.exists(transcript_path):
            print(f"[!] Error: Transcript file not found: {transcript_path}")
            return 1
        
        receipt_path = input("Enter SessionReceipt JSON path: ").strip()
        if not os.path.exists(receipt_path):
            print(f"[!] Error: Receipt file not found: {receipt_path}")
            return 1
        
        cert_path = input("Enter peer certificate path (PEM): ").strip()
        if not os.path.exists(cert_path):
            print(f"[!] Error: Certificate file not found: {cert_path}")
            return 1
        
        print()
        
    except KeyboardInterrupt:
        print("\n[!] Aborted by user")
        return 1
    
    # Load files
    print(f"[*] Loading transcript: {transcript_path}")
    messages = load_transcript(transcript_path)
    print(f"[+] Loaded {len(messages)} messages")
    
    print(f"[*] Loading receipt: {receipt_path}")
    receipt = load_receipt(receipt_path)
    print(f"[+] Receipt peer: {receipt['peer']}, seq range: {receipt['first_seq']}-{receipt['last_seq']}")
    
    print(f"[*] Loading peer certificate: {cert_path}")
    peer_cert = load_certificate(cert_path)
    subject = peer_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    print(f"[+] Certificate CN: {subject}")
    
    # Perform verifications
    sig_success, sig_total = verify_message_signatures(messages, peer_cert)
    hash_valid = verify_transcript_integrity(transcript_path, receipt)
    receipt_valid = verify_receipt_signature(receipt, peer_cert)
    
    # Print summary
    success = print_summary(sig_success, sig_total, hash_valid, receipt_valid)
    
    return 0 if success else 1


if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
