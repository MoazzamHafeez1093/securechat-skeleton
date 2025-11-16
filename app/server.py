"""
SecureChat Server
Handles client connections, authentication, and encrypted messaging
"""

import socket
import json
import base64
import time
import os
import sys
import select
from dotenv import load_dotenv
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
import random

# Import utility modules
from app.crypto.aes import aes_encrypt, aes_decrypt
from app.crypto.pki import load_certificate, load_private_key, validate_certificate
from app.crypto.dh import generate_dh_keypair, compute_shared_secret, derive_aes_key_from_dh
from app.crypto.sign import rsa_sign, rsa_verify, compute_message_hash
from app.common.utils import b64e, b64d, sha256_hex, now_ms, int_to_bytes, bytes_to_int, compute_cert_fingerprint
from app.storage.db import UserDB

# Load environment variables
load_dotenv()

class SecureChatServer:
    def __init__(self):
        self.host = os.getenv('SERVER_HOST', '127.0.0.1')
        self.port = int(os.getenv('SERVER_PORT', 5000))
        self.ca_cert_path = "certs/ca_cert.pem"
        self.server_cert_path = "certs/server_cert.pem"
        self.server_key_path = "certs/server_key.pem"
        
        # Load CA certificate
        self.ca_cert = load_certificate(self.ca_cert_path)
        
        # Load server certificate and key
        self.server_cert = load_certificate(self.server_cert_path)
        self.server_key = load_private_key(self.server_key_path)
        self.server_cert_pem = self.server_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        
        # Initialize database connection
        self.db = UserDB()
        
        # Session variables
        self.client_cert = None
        self.client_cert_pem = None
        self.session_key = None
        self.temp_key = None
        self.last_seqno = 0
        self.transcript_file = None
        self.username = None
        
        print(f"[*] Server initialized on {self.host}:{self.port}")
    
    def send_json(self, conn, data):
        """Send JSON data over socket"""
        message = json.dumps(data).encode('utf-8')
        conn.sendall(len(message).to_bytes(4, 'big') + message)
    
    def recv_json(self, conn):
        """Receive JSON data from socket"""
        length_bytes = conn.recv(4)
        if not length_bytes:
            return None
        length = int.from_bytes(length_bytes, 'big')
        data = b''
        while len(data) < length:
            chunk = conn.recv(length - len(data))
            if not chunk:
                return None
            data += chunk
        return json.loads(data.decode('utf-8'))
    
    def handle_certificate_exchange(self, conn):
        """Phase 1: Certificate exchange and validation"""
        print("\n[*] Phase 1: Certificate Exchange")
        
        # Receive client hello with certificate
        client_hello = self.recv_json(conn)
        if client_hello['type'] != 'hello':
            print("ERROR: Expected hello message")
            return False
        
        self.client_cert_pem = client_hello['client_cert']
        client_nonce = client_hello['nonce']
        
        print("[*] Received client certificate")
        
        # Parse and validate client certificate
        self.client_cert = x509.load_pem_x509_certificate(self.client_cert_pem.encode())
        is_valid, message = validate_certificate(self.client_cert, self.ca_cert)
        if not is_valid:
            print(f"[!] {message}")
            self.send_json(conn, {'type': 'error', 'message': message})
            return False
        
        print(f"[✓] Client certificate validated: {message}")
        
        # Send server hello with certificate
        server_nonce = base64.b64encode(os.urandom(16)).decode('utf-8')
        self.send_json(conn, {
            'type': 'server_hello',
            'server_cert': self.server_cert_pem,
            'nonce': server_nonce
        })
        
        print("[✓] Certificate exchange complete")
        return True
    
    def handle_temp_dh_exchange(self, conn):
        """Temporary DH for registration/login encryption"""
        print("\n[*] Temporary DH Exchange for Credentials")
        
        # Receive DH parameters from client
        dh_msg = self.recv_json(conn)
        p = dh_msg['p']
        g = dh_msg['g']
        A = dh_msg['A']
        
        # Generate server's DH private key
        b = random.randint(2, p - 2)
        B = pow(g, b, p)
        
        # Send B to client
        self.send_json(conn, {'type': 'dh_server', 'B': B})
        
        # Compute shared secret
        Ks = pow(A, b, p)
        Ks_bytes = int_to_bytes(Ks)
        
        # Derive temporary AES key
        self.temp_key = derive_aes_key_from_dh(Ks)
        
        print(f"[✓] Temporary session key established")
        return True
    
    def handle_registration(self, conn):
        """Handle user registration"""
        print("\n[*] Processing Registration")
        
        # Receive encrypted registration data
        reg_msg = self.recv_json(conn)
        encrypted_data = base64.b64decode(reg_msg['data'])
        
        # Decrypt with temporary key
        plaintext = aes_decrypt(encrypted_data, self.temp_key)
        reg_data = json.loads(plaintext)
        
        email = reg_data['email']
        username = reg_data['username']
        password = reg_data['password']
        
        print(f"[*] Registration request for: {username} ({email})")
        
        # Register user in database
        success, message = self.db.register_user(email, username, password)
        
        if success:
            print(f"[✓] {message}")
            self.send_json(conn, {'type': 'reg_response', 'success': True, 'message': message})
            return True
        else:
            print(f"[!] {message}")
            self.send_json(conn, {'type': 'reg_response', 'success': False, 'message': message})
            return False
    
    def handle_login(self, conn):
        """Handle user login"""
        print("\n[*] Processing Login")
        
        # Receive encrypted login data
        login_msg = self.recv_json(conn)
        if 'data' not in login_msg:
            print(f"[!] Error: Invalid login message format: {login_msg}")
            self.send_json(conn, {'type': 'login_response', 'success': False, 'message': 'Invalid message format'})
            return False
        encrypted_data = base64.b64decode(login_msg['data'])
        
        # Decrypt with temporary key
        plaintext = aes_decrypt(encrypted_data, self.temp_key)
        login_data = json.loads(plaintext)
        
        email = login_data['email']
        password = login_data['password']
        
        print(f"[*] Login attempt for: {email}")
        
        # Authenticate user
        success, username_or_error = self.db.verify_login(email, password)
        
        if success:
            self.username = username_or_error
            print(f"[✓] Login successful: {self.username}")
            self.send_json(conn, {'type': 'login_response', 'success': True, 'username': self.username})
            return True
        else:
            print(f"[!] Login failed: {username_or_error}")
            self.send_json(conn, {'type': 'login_response', 'success': False, 'message': username_or_error})
            return False
    
    def handle_session_dh_exchange(self, conn):
        """Session DH for chat encryption"""
        print("\n[*] Session DH Key Exchange")
        
        # Receive DH parameters from client
        dh_msg = self.recv_json(conn)
        p = dh_msg['p']
        g = dh_msg['g']
        A = dh_msg['A']
        
        # Generate server's DH private key
        b = random.randint(2, p - 2)
        B = pow(g, b, p)
        
        # Send B to client
        self.send_json(conn, {'type': 'dh_server', 'B': B})
        
        # Compute shared secret
        Ks = pow(A, b, p)
        Ks_bytes = int_to_bytes(Ks)
        
        # Derive session AES key
        self.session_key = derive_aes_key_from_dh(Ks)
        
        print(f"[✓] Session key established")
        
        # Initialize transcript
        timestamp = int(time.time())
        self.transcript_file = f"transcripts/server_{self.username}_{timestamp}.txt"
        os.makedirs("transcripts", exist_ok=True)
        
        return True
    
    def append_to_transcript(self, seqno, ts, ct, sig, peer_fingerprint):
        """Append message to transcript"""
        line = f"{seqno}|{ts}|{base64.b64encode(ct).decode()}|{base64.b64encode(sig).decode()}|{peer_fingerprint}\n"
        with open(self.transcript_file, "a") as f:
            f.write(line)
    
    def handle_message(self, conn, msg):
        """Handle incoming chat message"""
        seqno = msg['seqno']
        ts = msg['ts']
        ct = base64.b64decode(msg['ct'])
        sig = base64.b64decode(msg['sig'])
        
        # Replay protection
        if seqno <= self.last_seqno:
            print(f"[!] REPLAY: Rejected message with seqno {seqno}")
            return False
        
        # Recompute hash
        computed_hash = compute_message_hash(seqno, ts, ct)
        
        # Verify signature
        try:
            client_public_key = self.client_cert.public_key()
            client_public_key.verify(
                sig,
                computed_hash,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        except Exception as e:
            print(f"[!] SIG_FAIL: Invalid signature - {str(e)}")
            return False
        
        # Decrypt message
        try:
            plaintext = aes_decrypt(ct, self.session_key)
            print(f"\n[{self.username}]: {plaintext}")
        except Exception as e:
            print(f"[!] Decryption failed: {str(e)}")
            return False
        
        # Log to transcript
        client_fingerprint = compute_cert_fingerprint(self.client_cert)
        self.append_to_transcript(seqno, ts, ct, sig, client_fingerprint)
        
        self.last_seqno = seqno
        return True
    
    def send_message(self, conn, plaintext, seqno):
        """Send encrypted and signed message"""
        ts = int(time.time() * 1000)
        
        # Encrypt
        ct = aes_encrypt(plaintext, self.session_key)
        
        # Compute hash and sign
        h = compute_message_hash(seqno, ts, ct)
        sig = rsa_sign(h, self.server_key)
        
        # Send
        msg = {
            'type': 'msg',
            'seqno': seqno,
            'ts': ts,
            'ct': base64.b64encode(ct).decode(),
            'sig': base64.b64encode(sig).decode()
        }
        self.send_json(conn, msg)
        
        # Log to transcript
        server_fingerprint = compute_cert_fingerprint(self.server_cert)
        self.append_to_transcript(seqno, ts, ct, sig, server_fingerprint)
    
    def generate_session_receipt(self):
        """Generate SessionReceipt for non-repudiation"""
        if not self.transcript_file or not os.path.exists(self.transcript_file):
            print("[!] No transcript file to generate receipt")
            return None
            
        print("\n[*] Generating SessionReceipt...")
        
        with open(self.transcript_file, "r") as f:
            lines = f.readlines()
        
        if not lines:
            print("[!] No messages in transcript")
            return None
        
        first_seq = int(lines[0].split('|')[0])
        last_seq = int(lines[-1].split('|')[0])
        
        # Compute transcript hash
        full_transcript = "".join(lines)
        transcript_hash = sha256_hex(full_transcript)
        
        # Sign the hash
        sig = rsa_sign(bytes.fromhex(transcript_hash), self.server_key)
        
        receipt = {
            'type': 'receipt',
            'peer': 'server',
            'first_seq': first_seq,
            'last_seq': last_seq,
            'transcript_sha256': transcript_hash,
            'sig': base64.b64encode(sig).decode()
        }
        
        # Save receipt
        os.makedirs("receipts", exist_ok=True)
        receipt_file = self.transcript_file.replace("transcripts/", "receipts/").replace(".txt", "_receipt.json")
        with open(receipt_file, "w") as f:
            json.dump(receipt, f, indent=2)
        
        print(f"[✓] SessionReceipt saved to: {receipt_file}")
        return receipt
    
    def chat_loop(self, conn):
        """Main chat loop"""
        print("\n[*] Entering chat mode. Type your messages (or 'quit' to exit)")
        
        server_seqno = 0
        
        try:
            while True:
                # Check for incoming messages (non-blocking would be better, but keeping it simple)
                conn.settimeout(0.1)
                try:
                    msg = self.recv_json(conn)
                    if msg:
                        if msg['type'] == 'msg':
                            if not self.handle_message(conn, msg):
                                continue
                        elif msg['type'] == 'quit':
                            print(f"\n[*] Client disconnected")
                            break
                except socket.timeout:
                    pass
                
                # Check for server input (skip on Windows as select doesn't work with stdin)
                try:
                    if sys.platform != 'win32' and select.select([sys.stdin], [], [], 0)[0]:
                        message = input()
                        if message.lower() == 'quit':
                            self.send_json(conn, {'type': 'quit'})
                            break
                        
                        server_seqno += 1
                        self.send_message(conn, message, server_seqno)
                except (OSError, ValueError):
                    # stdin not available or Windows platform
                    pass
                
        except KeyboardInterrupt:
            print("\n[*] Server shutting down...")
        finally:
            # Generate receipt
            self.generate_session_receipt()
    
    def handle_client(self, conn, addr):
        """Handle individual client connection"""
        print(f"\n[*] Client connected from {addr}")
        
        try:
            # Phase 1: Certificate Exchange
            if not self.handle_certificate_exchange(conn):
                return
            
            # Phase 2: Temporary DH for credentials
            if not self.handle_temp_dh_exchange(conn):
                return
            
            # Phase 3: Registration or Login
            auth_choice = self.recv_json(conn)
            if auth_choice['action'] == 'register':
                if not self.handle_registration(conn):
                    return
                # After registration, proceed to login
                if not self.handle_temp_dh_exchange(conn):
                    return
                # Receive login action message
                login_choice = self.recv_json(conn)
                if login_choice.get('action') != 'login':
                    print("[!] Expected login after registration")
                    return
                if not self.handle_login(conn):
                    return
            elif auth_choice['action'] == 'login':
                if not self.handle_login(conn):
                    return
            else:
                print("[!] Invalid authentication choice")
                return
            
            # Phase 4: Session DH Key Exchange
            if not self.handle_session_dh_exchange(conn):
                return
            
            # Phase 5: Chat Loop
            self.chat_loop(conn)
            
        except Exception as e:
            print(f"[!] Error: {str(e)}")
            import traceback
            traceback.print_exc()
        finally:
            conn.close()
            print(f"[*] Connection closed")
    
    def start(self):
        """Start the server"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(1)
        
        print(f"[*] Server listening on {self.host}:{self.port}")
        print("[*] Waiting for client connection...")
        
        try:
            while True:
                conn, addr = sock.accept()
                self.handle_client(conn, addr)
                # Reset for next connection
                self.__init__()
        except KeyboardInterrupt:
            print("\n[*] Server stopped")
        finally:
            sock.close()

if __name__ == "__main__":
    import sys
    server = SecureChatServer()
    server.start()