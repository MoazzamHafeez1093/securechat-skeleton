"""Append-only transcript + TranscriptHash helpers."""
import os
import hashlib
import json
from typing import Optional
from ..common.utils import b64e


class Transcript:
    """
    Manages append-only session transcript for non-repudiation.
    
    Transcript format per message (pipe-delimited):
    seqno | timestamp | ciphertext_base64 | signature_base64 | peer_cert_fingerprint
    """
    
    def __init__(self, filepath: str):
        """
        Initialize transcript file.
        
        Args:
            filepath: path to transcript file (will be created if doesn't exist)
        """
        self.filepath = filepath
        self.first_seq: Optional[int] = None
        self.last_seq: Optional[int] = None
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        # Create empty file if doesn't exist
        if not os.path.exists(filepath):
            with open(filepath, 'w') as f:
                pass
    
    def append_message(
        self, 
        seqno: int, 
        timestamp: int, 
        ciphertext: bytes, 
        signature: bytes,
        peer_cert_fingerprint: str
    ) -> None:
        """
        Append a message entry to the transcript.
        
        Args:
            seqno: sequence number
            timestamp: Unix timestamp in milliseconds
            ciphertext: encrypted message bytes
            signature: RSA signature bytes
            peer_cert_fingerprint: SHA-256 fingerprint of peer's certificate
        """
        # Track sequence number range
        if self.first_seq is None:
            self.first_seq = seqno
        self.last_seq = seqno
        
        # Format: seqno|ts|ct|sig|fingerprint
        line = f"{seqno}|{timestamp}|{b64e(ciphertext)}|{b64e(signature)}|{peer_cert_fingerprint}\n"
        
        # Append to file (append-only)
        with open(self.filepath, 'a') as f:
            f.write(line)
    
    def compute_transcript_hash(self) -> str:
        """
        Compute SHA-256 hash of entire transcript.
        
        Returns:
            Hex-encoded SHA-256 hash of concatenated transcript lines
        """
        with open(self.filepath, 'r', encoding='utf-8') as f:
            transcript_text = f.read()
        
        return hashlib.sha256(transcript_text.encode('utf-8')).hexdigest()
    
    def generate_session_receipt(
        self, 
        peer: str,
        signature: bytes
    ) -> dict:
        """
        Generate SessionReceipt for non-repudiation.
        
        Format per assignment:
        {
            "type": "receipt",
            "peer": "client|server",
            "first_seq": int,
            "last_seq": int,
            "transcript_sha256": hex,
            "sig": base64(RSA_SIGN(transcript_sha256))
        }
        
        Args:
            peer: "client" or "server"
            signature: RSA signature over transcript hash
            
        Returns:
            SessionReceipt dict
        """
        transcript_hash = self.compute_transcript_hash()
        
        return {
            "type": "receipt",
            "peer": peer,
            "first_seq": self.first_seq or 0,
            "last_seq": self.last_seq or 0,
            "transcript_sha256": transcript_hash,
            "sig": b64e(signature)
        }
    
    def save_receipt(self, receipt: dict, receipt_path: str) -> None:
        """
        Save SessionReceipt to JSON file.
        
        Args:
            receipt: SessionReceipt dict
            receipt_path: path to save receipt file
        """
        os.makedirs(os.path.dirname(receipt_path), exist_ok=True)
        
        with open(receipt_path, 'w') as f:
            json.dump(receipt, f, indent=2)
    
    def get_message_count(self) -> int:
        """
        Get total number of messages in transcript.
        
        Returns:
            Number of lines in transcript file
        """
        try:
            with open(self.filepath, 'r') as f:
                return sum(1 for _ in f)
        except FileNotFoundError:
            return 0
