"""
SecureChat Client
Connects to server, authenticates, and sends/receives encrypted messages
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

# Load environment variables
load_dotenv()

class SecureChatClient:
    def __init__(self):
        self.host = os.getenv('SERVER_HOST', '127.0.0.1')
        self.port = int(os.getenv('SERVER_PORT', 5000))
        self.ca_cert_path = "certs/ca_cert.pem"
        self.client_cert_path = "certs/client_cert.pem"
        self.client_key_path = "certs/client_key.pem"
        
        # Load CA certificate
        self.ca_cert = load_certificate(self.ca_cert_path)
        
        # Load client certificate and key
        self.client_cert = load_certificate(self.client_cert_path)
        self.client_key = load_private_key(self.client_key_path)
        self.client_cert_pem = self.client_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        
        # Session variables
        self.server_cert = None
        self.server_cert_pem = None
        self.session_key = None
        self.temp_key = None
        self.last_seqno = 0
        self.transcript_file = None
        self.username = None
        self.sock = None
        
        print(f"[*] Client initialized")
    
    def send_json(self, data):
        """Send JSON data over socket"""
        message = json.dumps(data).encode('utf-8')
        self.sock.sendall(len(message).to_bytes(4, 'big') + message)
    
    def recv_json(self):
        """Receive JSON data from socket"""
        length_bytes = self.sock.recv(4)
        if not length_bytes:
            return None
        length = int.from_bytes(length_bytes, 'big')
        data = b''
        while len(data) < length:
            chunk = self.sock.recv(length - len(data))
            if not chunk:
                return None
            data += chunk
        return json.loads(data.decode('utf-8'))
    
    def connect(self):
        """Connect to server"""
        print(f"[*] Connecting to {self.host}:{self.port}...")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        print("[✓] Connected to server")
    
    def certificate_exchange(self):
        """Phase 1: Certificate exchange and validation"""
        print("\n[*] Phase 1: Certificate Exchange")
        
        # Send client hello with certificate
        client_nonce = base64.b64encode(os.urandom(16)).decode('utf-8')
        self.send_json({
            'type': 'hello',
            'client_cert': self.client_cert_pem,
            'nonce': client_nonce
        })
        
        print("[*] Sent client certificate")
        
        # Receive server hello with certificate
        server_hello = self.recv_json()
        if server_hello['type'] != 'server_hello':
            print("ERROR: Expected server_hello")
            return False
        
        self.server_cert_pem = server_hello['server_cert']
        server_nonce = server_hello['nonce']
        
        print("[*] Received server certificate")
        
        # Parse and validate server certificate
        self.server_cert = x509.load_pem_x509_certificate(self.server_cert_pem.encode())
        is_valid, message = validate_certificate(self.server_cert, self.ca_cert, "SecureChat Server")
        if not is_valid:
            print(f"[!] {message}")
            return False
        
        print(f"[✓] Server certificate validated: {message}")
        
        return True
    
    def temp_dh_exchange(self):
        """Temporary DH for registration/login encryption"""
        print("\n[*] Temporary DH Exchange for Credentials")
        
        # DH parameters (using safe prime)
        p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        g = 2
        
        # Generate client's private key
        a = random.randint(2, p - 2)
        A = pow(g, a, p)
        
        # Send DH parameters
        self.send_json({
            'type': 'dh_client',
            'p': p,
            'g': g,
            'A': A
        })
        
        # Receive server's public value
        dh_response = self.recv_json()
        B = dh_response['B']
        
        # Compute shared secret
        Ks = pow(B, a, p)
        Ks_bytes = int_to_bytes(Ks)
        
        # Derive temporary AES key
        self.temp_key = derive_aes_key_from_dh(Ks)
        
        print(f"[✓] Temporary session key established")
        return True
    
    def register(self):
        """Register new user"""
        print("\n=== REGISTRATION ===")
        email = input("Email: ")
        username = input("Username: ")
        password = input("Password: ")
        
        # Encrypt registration data with temporary key
        reg_data = json.dumps({
            'email': email,
            'username': username,
            'password': password
        })
        
        encrypted_data = aes_encrypt(reg_data, self.temp_key)
        
        # Send encrypted registration
        self.send_json({
            'type': 'register',
            'data': base64.b64encode(encrypted_data).decode()
        })
        
        # Receive response
        response = self.recv_json()
        if response is None:
            print("[!] Server disconnected during registration")
            return False
        
        if response.get('success'):
            print(f"[✓] {response['message']}")
            return True
        else:
            print(f"[!] {response.get('message', 'Registration failed')}")
            return False
    
    def login(self):
        """Login existing user"""
        print("\n=== LOGIN ===")
        email = input("Email: ")
        password = input("Password: ")
        
        # Encrypt login data with temporary key
        login_data = json.dumps({
            'email': email,
            'password': password
        })
        
        encrypted_data = aes_encrypt(login_data, self.temp_key)
        
        # Send encrypted login
        self.send_json({
            'type': 'login',
            'data': base64.b64encode(encrypted_data).decode()
        })
        
        # Receive response
        response = self.recv_json()
        if response is None:
            print("[!] Server disconnected during login")
            return False
        
        if response.get('success'):
            self.username = response.get('username')
            print(f"[✓] Welcome back, {self.username}!")
            return True
        else:
            print(f"[!] {response.get('message', 'Login failed')}")
            return False
    
    def session_dh_exchange(self):
        """Session DH for chat encryption"""
        print("\n[*] Session DH Key Exchange")
        
        # DH parameters
        p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        g = 2
        
        # Generate client's private key
        a = random.randint(2, p - 2)
        A = pow(g, a, p)
        
        # Send DH parameters
        self.send_json({
            'type': 'dh_client',
            'p': p,
            'g': g,
            'A': A
        })
        
        # Receive server's public value
        dh_response = self.recv_json()
        B = dh_response['B']
        
        # Compute shared secret
        Ks = pow(B, a, p)
        Ks_bytes = int_to_bytes(Ks)
        
        # Derive session AES key
        self.session_key = derive_aes_key_from_dh(Ks)
        
        print(f"[✓] Session key established")
        
        # Initialize transcript
        timestamp = int(time.time())
        self.transcript_file = f"transcripts/client_{self.username}_{timestamp}.txt"
        os.makedirs("transcripts", exist_ok=True)
        
        return True
    
    def append_to_transcript(self, seqno, ts, ct, sig, peer_fingerprint):
        """Append message to transcript"""
        line = f"{seqno}|{ts}|{base64.b64encode(ct).decode()}|{base64.b64encode(sig).decode()}|{peer_fingerprint}\n"
        with open(self.transcript_file, "a") as f:
            f.write(line)
    
    def handle_message(self, msg):
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
            server_public_key = self.server_cert.public_key()
            server_public_key.verify(
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
            print(f"\n[Server]: {plaintext}")
        except Exception as e:
            print(f"[!] Decryption failed: {str(e)}")
            return False
        
        # Log to transcript
        server_fingerprint = compute_cert_fingerprint(self.server_cert)
        self.append_to_transcript(seqno, ts, ct, sig, server_fingerprint)
        
        self.last_seqno = seqno
        return True
    
    def send_message(self, plaintext, seqno):
        """Send encrypted and signed message"""
        ts = int(time.time() * 1000)
        
        # Encrypt
        ct = aes_encrypt(plaintext, self.session_key)
        
        # Compute hash and sign
        h = compute_message_hash(seqno, ts, ct)
        sig = rsa_sign(h, self.client_key)
        
        # Send
        msg = {
            'type': 'msg',
            'seqno': seqno,
            'ts': ts,
            'ct': base64.b64encode(ct).decode(),
            'sig': base64.b64encode(sig).decode()
        }
        self.send_json(msg)
        
        # Log to transcript
        client_fingerprint = compute_cert_fingerprint(self.client_cert)
        self.append_to_transcript(seqno, ts, ct, sig, client_fingerprint)
    
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
        sig = rsa_sign(bytes.fromhex(transcript_hash), self.client_key)
        
        receipt = {
            'type': 'receipt',
            'peer': 'client',
            'first_seq': first_seq,
            'last_seq': last_seq,
            'transcript_sha256': transcript_hash,
            'sig': base64.b64encode(sig).decode()
        }
        
        # Save receipt
        receipt_file = self.transcript_file.replace("transcripts/", "receipts/").replace(".txt", "_receipt.json")
        os.makedirs(os.path.dirname(receipt_file), exist_ok=True)
        with open(receipt_file, "w") as f:
            json.dump(receipt, f, indent=2)
        
        print(f"[✓] SessionReceipt saved to: {receipt_file}")
        return receipt
    
    def chat_loop(self):
        """Main chat loop"""
        print("\n" + "="*50)
        print(f"   SECURE CHAT - Logged in as: {self.username}")
        print("="*50)
        print("Type your messages (or 'quit' to exit)\n")
        
        client_seqno = 0
        
        try:
            while True:
                # Check for incoming messages
                self.sock.settimeout(0.1)
                try:
                    msg = self.recv_json()
                    if msg:
                        if msg['type'] == 'msg':
                            if not self.handle_message(msg):
                                continue
                        elif msg['type'] == 'quit':
                            print(f"\n[*] Server disconnected")
                            break
                except socket.timeout:
                    pass
                
                # Check for user input
                if select.select([sys.stdin], [], [], 0)[0]:
                    message = input()
                    if message.lower() == 'quit':
                        self.send_json({'type': 'quit'})
                        break
                    
                    if message.strip():  # Don't send empty messages
                        client_seqno += 1
                        self.send_message(message, client_seqno)
                
        except KeyboardInterrupt:
            print("\n[*] Disconnecting...")
        finally:
            # Generate receipt
            self.generate_session_receipt()
    
    def start(self):
        """Start the client"""
        try:
            # Connect to server
            self.connect()
            
            # Certificate exchange
            if not self.certificate_exchange():
                return
            
            # Temporary DH for credentials
            if not self.temp_dh_exchange():
                return
            
            # Authentication
            print("\n" + "="*50)
            choice = input("Choose: (1) Register  (2) Login\nChoice: ")
            
            if choice == '1':
                self.send_json({'action': 'register'})
                if not self.register():
                    return
                
                # After registration, login
                print("\n[*] Please login with your new account")
                if not self.temp_dh_exchange():
                    return
                self.send_json({'action': 'login'})
                if not self.login():
                    return
                    
            elif choice == '2':
                self.send_json({'action': 'login'})
                if not self.login():
                    return
            else:
                print("[!] Invalid choice")
                return
            
            # Session DH key exchange
            if not self.session_dh_exchange():
                return
            
            # Start chatting
            self.chat_loop()
            
        except Exception as e:
            print(f"[!] Error: {str(e)}")
            import traceback
            traceback.print_exc()
        finally:
            if self.sock:
                self.sock.close()
            print("[*] Disconnected")

if __name__ == "__main__":
    client = SecureChatClient()
    client.start()