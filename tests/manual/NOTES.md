# SecureChat Manual Testing Checklist

## 🧪 Test Evidence Requirements (Assignment #2)

### 1. ✅ Wireshark Capture - Encrypted Payloads Only
**Objective:** Demonstrate that all sensitive data is encrypted at the application layer.

**Detailed Test Steps:**

#### Step 1: Install Wireshark (if not installed)
- Download from: https://www.wireshark.org/download.html
- Install with default options
- On Windows: May require WinPcap/Npcap driver installation

#### Step 2: Start Wireshark Capture
1. Open Wireshark
2. Select "Adapter for loopback traffic capture" or "Loopback: lo0" interface
3. Click the blue shark fin icon (Start capturing packets)
4. Apply display filter: `tcp.port == 5000` (assuming server uses port 5000)

#### Step 3: Run Test Session
```powershell
# Terminal 1 - Server
cd D:\infosec_assignment2\securechat-skeleton
python -m app.server

# Terminal 2 - Client
cd D:\infosec_assignment2\securechat-skeleton
python -m app.client
```

#### Step 4: Perform Actions
1. Login with existing user (e.g., `usi` / password: `432`)
2. Send at least 5 chat messages:
   - "Test message 1"
   - "This should be encrypted"
   - "Verifying Wireshark capture"
   - "Checking for plaintext leaks"
   - "Final test message"
3. Type `quit` to disconnect gracefully

#### Step 5: Stop Capture & Save
1. Click red square (Stop capturing)
2. File → Save As → `wireshark-encrypted-traffic.pcapng`
3. Save to `tests/manual/evidence/` directory

#### Step 6: Analyze Capture
1. Right-click any packet → Follow → TCP Stream
2. Verify you see:
   - ✓ JSON structure: `{"action": "...", "ct": "..."}`
   - ✓ Base64-encoded ciphertext (random-looking strings)
   - ✗ NO plaintext passwords
   - ✗ NO plaintext chat messages
   - ✗ NO plaintext usernames in encrypted fields

**Expected Result:**
- TCP packets visible with JSON protocol messages
- All sensitive fields (`ct`, `pwd_hash`) are Base64-encoded ciphertext
- Chat message content NOT readable as plaintext
- Only protocol metadata (action types, sequence numbers) visible

**Evidence File:** `tests/manual/evidence/wireshark-encrypted-traffic.pcapng`
**Screenshot:** TCP stream showing encrypted JSON payloads

---

### 2. ✅ BAD_CERT - Invalid/Self-Signed Certificate Rejection
**Objective:** Verify certificate validation rejects invalid certificates.

**Test Scenarios:**

#### Scenario A: Self-Signed Certificate (Not CA-Signed)
**Steps:**
1. Backup current certificates:
```powershell
cd D:\infosec_assignment2\securechat-skeleton\certs
copy server_cert.pem server_cert.pem.backup
copy server_key.pem server_key.pem.backup
```

2. Generate self-signed certificate (NOT signed by CA):
```powershell
openssl req -x509 -newkey rsa:2048 -nodes -keyout server_key.pem -out server_cert.pem -days 365 -subj "/CN=localhost"
```

3. Start server:
```powershell
python -m app.server
```

4. Run client:
```powershell
python -m app.client
```

5. Observe rejection during certificate exchange phase

**Expected Output:**
```
[!] BAD_CERT: Certificate validation failed - not signed by trusted CA
Connection terminated.
```

6. Restore original certificates:
```powershell
cd certs
copy server_cert.pem.backup server_cert.pem
copy server_key.pem.backup server_key.pem
```

---

#### Scenario B: Expired Certificate
**Steps:**
1. Generate expired certificate (valid from past, expired yesterday):
```powershell
cd certs
# Generate cert valid from Jan 1, 2023 to Jan 2, 2023 (expired)
openssl req -x509 -newkey rsa:2048 -nodes -keyout expired_key.pem -out expired_cert.pem -days 1 -subj "/CN=localhost"
# Manually backdate using OpenSSL or wait 2 days
```

2. Backup and replace server certificate:
```powershell
copy server_cert.pem server_cert.pem.backup
copy expired_cert.pem server_cert.pem
```

3. Run server and client

**Expected Output:**
```
[!] BAD_CERT: Certificate has expired
Connection terminated.
```

4. Restore backup

---

#### Scenario C: Wrong Common Name / Wrong Certificate
**Steps:**
1. Use client certificate as server certificate:
```powershell
cd certs
copy server_cert.pem server_cert.pem.backup
copy client_cert.pem server_cert.pem
```

2. Run server and client

**Expected Output:**
```
[!] BAD_CERT: Certificate CN mismatch (expected 'server', got 'client')
Connection terminated.
```

3. Restore:
```powershell
copy server_cert.pem.backup server_cert.pem
```

**Evidence Required:**
- Screenshot of each rejection message
- Console output saved to text files: `bad_cert_test_A.txt`, `bad_cert_test_B.txt`, `bad_cert_test_C.txt`
- Save to: `tests/manual/evidence/`

---

### 3. ✅ SIG_FAIL - Tamper Detection via Signature Verification
**Objective:** Demonstrate that message tampering is detected through signature verification failure.

**Detailed Test Steps:**

#### Method 1: Manual Network Interception (Advanced)
Use a man-in-the-middle proxy to tamper with messages in transit.

#### Method 2: Automated Test Script (Recommended)
Create a test script to simulate tampering.

**Step 1: Create Tamper Test Script**
Create file: `tests/manual/test_tamper.py`

```python
import socket
import json
import base64
import sys

def test_tamper_detection():
    """
    Simulate message tampering by flipping bits in ciphertext.
    """
    print("[*] Starting SIG_FAIL tamper test...")
    
    # Connect to server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('localhost', 5000))
    
    # Perform cert exchange, login, session DH
    # (simplified - copy logic from client.py)
    # ...
    
    # Send valid message
    valid_msg = {
        "action": "chat",
        "seqno": 1,
        "ts": 1700000000000,
        "ct": "dmFsaWRfY2lwaGVydGV4dA==",  # Valid encrypted content
        "sig": "valid_signature_base64..."  # Valid signature
    }
    sock.sendall(json.dumps(valid_msg).encode() + b'\n')
    print("[+] Sent valid message")
    
    # Tamper with message
    tampered_msg = valid_msg.copy()
    ct_bytes = base64.b64decode(tampered_msg['ct'])
    # Flip first bit
    tampered = bytes([ct_bytes[0] ^ 0x01]) + ct_bytes[1:]
    tampered_msg['ct'] = base64.b64encode(tampered).decode()
    
    print("[*] Sending tampered message (bit flipped in ciphertext)...")
    sock.sendall(json.dumps(tampered_msg).encode() + b'\n')
    
    # Server should reject with SIG_FAIL
    response = sock.recv(4096).decode()
    print(f"[<] Server response: {response}")
    
    if "SIG_FAIL" in response or "signature" in response.lower():
        print("✓ Test PASSED: Tamper detected!")
    else:
        print("✗ Test FAILED: Tamper not detected!")
    
    sock.close()

if __name__ == "__main__":
    test_tamper_detection()
```

**Step 2: Run Test**
```powershell
# Terminal 1 - Server
python -m app.server

# Terminal 2 - Run tamper test
python tests/manual/test_tamper.py
```

#### Method 3: Manual Testing with Modified Client (Easiest)
**Step 1: Modify client temporarily to inject tampered message**

In `app/client.py`, add a test function:

```python
def send_tampered_message(self):
    """Test function: send message with tampered ciphertext"""
    print("[TEST] Sending tampered message...")
    
    # Create valid message
    plaintext = "This is a test message"
    ciphertext = aes_encrypt(plaintext.encode(), self.session_key)
    seqno = self.seqno
    ts = now_ms()
    
    # Sign VALID message
    message_hash = compute_message_hash(seqno, ts, ciphertext)
    signature = rsa_sign(self.client_key, message_hash)
    
    # TAMPER: Flip one bit in ciphertext AFTER signing
    ct_bytes = ciphertext
    tampered_ct = bytes([ct_bytes[0] ^ 0x01]) + ct_bytes[1:]
    
    # Send tampered message
    msg = ChatMessage(
        seqno=seqno,
        ts=ts,
        ct=b64e(tampered_ct),  # Tampered ciphertext
        sig=b64e(signature)     # Valid signature for ORIGINAL
    )
    send_json(self.sock, msg.model_dump())
    self.seqno += 1
    
    print("[TEST] Tampered message sent - server should reject")
```

**Step 2: Run test**
1. Add call to `send_tampered_message()` in chat loop (press 't' key)
2. Run client and server
3. During chat, press 't' to trigger tamper test
4. Observe server rejection

**Expected Server Output:**
```
[!] SIG_FAIL: Message signature verification failed for seqno 5
[!] Rejecting tampered message from user: usi
```

**Expected Client Output:**
```
[TEST] Sending tampered message...
[TEST] Tampered message sent - server should reject
```

**Evidence Required:**
- Console screenshot showing `[!] SIG_FAIL` message
- Save server output: `tests/manual/evidence/sig_fail_test.txt`

---

### 4. ✅ REPLAY - Sequence Number Protection
**Objective:** Verify replay attack detection using sequence number validation.

**Detailed Test Steps:**

#### Method 1: Network Replay (Using Wireshark)
**Step 1: Capture Valid Message**
1. Run Wireshark during chat session
2. Send message with seqno=3
3. Capture the TCP packet containing JSON: `{"action":"chat","seqno":3,...}`
4. Save packet to file

**Step 2: Continue Session**
1. Send more messages (seqno=4, 5, 6)
2. Now expected seqno is 7

**Step 3: Replay Old Message**
1. Use `tcpreplay` or script to resend captured packet
2. Server receives seqno=3 again

**Expected Server Output:**
```
[!] REPLAY: Rejected message with seqno 3 (expected > 6)
```

#### Method 2: Automated Test Script (Recommended)
**Step 1: Create replay test script**

Create file: `tests/manual/test_replay.py`

```python
import socket
import json
import time

def test_replay_attack():
    """
    Test sequence number replay protection.
    """
    print("[*] Starting REPLAY attack test...")
    
    # Establish connection and session
    # (simplified - reuse client.py connection logic)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('localhost', 5000))
    
    # Perform handshake, login, etc.
    # ...
    
    # Send valid messages
    messages = []
    for i in range(1, 4):
        msg = {
            "action": "chat",
            "seqno": i,
            "ts": int(time.time() * 1000),
            "ct": f"message_{i}_encrypted",
            "sig": f"signature_{i}"
        }
        sock.sendall(json.dumps(msg).encode() + b'\n')
        messages.append(msg)
        print(f"[+] Sent message with seqno={i}")
        time.sleep(0.5)
    
    # Send one more fresh message
    msg = {
        "action": "chat",
        "seqno": 4,
        "ts": int(time.time() * 1000),
        "ct": "message_4_encrypted",
        "sig": "signature_4"
    }
    sock.sendall(json.dumps(msg).encode() + b'\n')
    print(f"[+] Sent message with seqno=4")
    
    # REPLAY: Resend message with seqno=2
    print("[*] REPLAYING message with seqno=2...")
    time.sleep(1)
    sock.sendall(json.dumps(messages[1]).encode() + b'\n')
    
    # Server should reject
    response = sock.recv(4096).decode()
    print(f"[<] Server response: {response}")
    
    if "REPLAY" in response or "sequence" in response.lower():
        print("✓ Test PASSED: Replay detected!")
    else:
        print("✗ Test FAILED: Replay not detected!")
    
    sock.close()

if __name__ == "__main__":
    test_replay_attack()
```

**Step 2: Run test**
```powershell
# Terminal 1 - Server
python -m app.server

# Terminal 2 - Replay test
python tests/manual/test_replay.py
```

#### Method 3: Manual Testing (Modify Client Code)
**Step 1: Add replay test function to client.py**

```python
def send_replay_message(self):
    """Test: Resend an old message"""
    if len(self.sent_messages) < 2:
        print("[!] Need at least 2 messages sent first")
        return
    
    # Resend the second message
    old_msg = self.sent_messages[1]  # Message with seqno=2
    print(f"[TEST] Replaying message with seqno={old_msg['seqno']} (current seqno={self.seqno})")
    
    send_json(self.sock, old_msg)
    print("[TEST] Replayed old message - server should reject")
```

**Step 2: During chat session**
1. Send 5 normal messages
2. Press 'r' key to trigger replay test
3. Observe server rejection

**Expected Server Output:**
```
[OK] Message 1 received
[OK] Message 2 received
[OK] Message 3 received
[OK] Message 4 received
[OK] Message 5 received
[!] REPLAY: Message seqno 2 rejected (expected > 5)
```

**Implementation Verification:**
Check that `app/server.py` includes replay protection:

```python
def handle_chat_message(self, msg):
    seqno = msg['seqno']
    
    # Replay protection
    if seqno <= self.last_received_seqno:
        print(f"[!] REPLAY: Rejected message with seqno {seqno} (expected > {self.last_received_seqno})")
        return False
    
    # Verify signature...
    # Process message...
    
    self.last_received_seqno = seqno  # Update
    return True
```

**Evidence Required:**
- Console screenshot showing `[!] REPLAY` rejection
- Save output: `tests/manual/evidence/replay_test.txt`

---

### 5. ✅ Non-Repudiation - Transcript & SessionReceipt Verification
**Objective:** Demonstrate offline verification of session transcripts with digital signatures.

**Detailed Test Steps:**

#### Part A: Generate Transcript During Chat Session
**Step 1: Complete a chat session**
```powershell
# Terminal 1 - Server
python -m app.server

# Terminal 2 - Client
python -m app.client
```

**Step 2: Send messages and quit**
1. Login with user: `usi` / password: `432`
2. Send at least 5 messages
3. Type `quit` to gracefully disconnect

**Step 3: Verify files created**
```powershell
cd transcripts
ls
# Should show:
# client_usi_<timestamp>.txt
# server_usi_<timestamp>.txt

cd ..\receipts
ls
# Should show:
# client_usi_<timestamp>_receipt.json
# server_usi_<timestamp>_receipt.json
```

**Step 4: Inspect transcript format**
```powershell
type transcripts\client_usi_<timestamp>.txt
```

**Expected Format:**
```
1|1763253118078|umWlFIFidq6j...|qPEitQnulxqlIej...|e8579772a56474575878660c
2|1763253124430|HPYkhtzwGuPP...|HTSdpRsDpFK/w9Y...|e8579772a56474575878660c
3|1763253127672|jeYCTxzDkNKr...|FYDMioQba+V3S8S...|e8579772a56474575878660c
```
Format: `seqno|timestamp|ciphertext_b64|signature_b64|peer_cert_fingerprint`

**Step 5: Inspect SessionReceipt**
```powershell
type receipts\server_usi_<timestamp>_receipt.json
```

**Expected Format:**
```json
{
  "type": "receipt",
  "peer": "server",
  "first_seq": 1,
  "last_seq": 5,
  "transcript_sha256": "6380615c969beacae8c5f5aae7c36062941a8fcc6f35bc95eb6c300d8b9c1e9d",
  "sig": "dEYE00eHqE8BMYn3L2O2Ws0IkqjMXm+DcdnLGYDuX0DLS4MMGJhIDjGX..."
}
```

---

#### Part B: Offline Verification (Success Case)
**Step 1: Run verification script**
```powershell
python scripts/verify_transcript.py
```

**Step 2: Provide inputs when prompted**
```
Enter transcript file path: transcripts/client_usi_1763253109.txt
Enter SessionReceipt JSON path: receipts/client_usi_1763253109_receipt.json
Enter peer certificate path: certs/server_cert.pem
```

**Expected Output:**
```
[*] Loading transcript: transcripts/client_usi_1763253109.txt
[*] Loading receipt: receipts/client_usi_1763253109_receipt.json
[*] Loading peer certificate: certs/server_cert.pem

=== Verifying Individual Message Signatures ===
[OK] Message 1 (seqno=1): Signature valid
[OK] Message 2 (seqno=2): Signature valid
[OK] Message 3 (seqno=3): Signature valid
[OK] Message 4 (seqno=4): Signature valid
[+] All 4 message signatures verified successfully

=== Verifying Transcript Integrity ===
[*] Computing SHA-256 hash of transcript...
[*] Expected: 6380615c969beacae8c5f5aae7c36062941a8fcc6f35bc95eb6c300d8b9c1e9d
[*] Computed: 6380615c969beacae8c5f5aae7c36062941a8fcc6f35bc95eb6c300d8b9c1e9d
[OK] Transcript hash matches!

=== Verifying SessionReceipt Signature ===
[*] Verifying receipt signature with peer's public key...
[OK] SessionReceipt signature valid

=====================================
✓ VERIFICATION PASSED
=====================================
Transcript is authentic and unmodified.
Non-repudiation: Peer cannot deny sending these messages.
```

---

#### Part C: Tamper Detection Test
**Step 1: Make a backup**
```powershell
copy transcripts\client_usi_1763253109.txt transcripts\client_usi_1763253109_backup.txt
```

**Step 2: Tamper with transcript**
Open `transcripts/client_usi_1763253109.txt` in text editor and:
- Change one character in the ciphertext field (column 3)
- Example: Change `umWlFIFidq6j...` to `umXlFIFidq6j...` (change 'W' to 'X')
- Save file

**Step 3: Re-run verification**
```powershell
python scripts/verify_transcript.py
```

**Expected Output:**
```
[*] Loading transcript: transcripts/client_usi_1763253109.txt
[*] Loading receipt: receipts/client_usi_1763253109_receipt.json
[*] Loading peer certificate: certs/server_cert.pem

=== Verifying Individual Message Signatures ===
[OK] Message 1 (seqno=1): Signature valid
[OK] Message 2 (seqno=2): Signature valid
[OK] Message 3 (seqno=3): Signature valid
[OK] Message 4 (seqno=4): Signature valid
[+] All 4 message signatures verified successfully

=== Verifying Transcript Integrity ===
[*] Computing SHA-256 hash of transcript...
[*] Expected: 6380615c969beacae8c5f5aae7c36062941a8fcc6f35bc95eb6c300d8b9c1e9d
[*] Computed: a7f8923bd4e2c1a9f0b5d8e6c3a2b1d9e4f6c8a7b5d3e1f9c2b4a6d8e0f2c4a6
[!] FAIL: Transcript hash mismatch!

=====================================
✗ VERIFICATION FAILED
=====================================
Transcript has been tampered with!
The transcript content does not match the SessionReceipt hash.
```

**Step 4: Restore original**
```powershell
copy transcripts\client_usi_1763253109_backup.txt transcripts\client_usi_1763253109.txt
```

---

#### Part D: Test Signature Tampering
**Step 1: Tamper with signature**
1. Open transcript file
2. Change one character in the signature field (column 4)
3. Save file

**Step 2: Run verification**

**Expected Output:**
```
=== Verifying Individual Message Signatures ===
[FAIL] Message 1 (seqno=1): Signature verification failed
[!] Message has been tampered with or signature is invalid

=====================================
✗ VERIFICATION FAILED
=====================================
One or more message signatures are invalid.
```

**Evidence Required:**
1. Screenshot of successful verification output
2. Screenshot of tamper detection (hash mismatch)
3. Screenshot of signature verification failure
4. Save outputs to:
   - `tests/manual/evidence/verify_success.txt`
   - `tests/manual/evidence/verify_tamper_detected.txt`
   - `tests/manual/evidence/verify_sig_fail.txt`

---

## 📝 Summary Checklist

### Evidence Files Required for Submission:

#### 1. Wireshark Evidence
- [ ] `tests/manual/evidence/wireshark-encrypted-traffic.pcapng` - Full packet capture
- [ ] `tests/manual/evidence/wireshark-screenshot.png` - TCP stream showing encrypted JSON

#### 2. BAD_CERT Tests
- [ ] `tests/manual/evidence/bad_cert_test_A.txt` - Self-signed cert rejection
- [ ] `tests/manual/evidence/bad_cert_test_B.txt` - Expired cert rejection
- [ ] `tests/manual/evidence/bad_cert_test_C.txt` - Wrong CN rejection
- [ ] Screenshots of each test

#### 3. SIG_FAIL Tests
- [ ] `tests/manual/evidence/sig_fail_test.txt` - Tamper detection output
- [ ] Screenshot showing rejection message

#### 4. REPLAY Tests
- [ ] `tests/manual/evidence/replay_test.txt` - Sequence number protection
- [ ] Screenshot showing rejection

#### 5. Non-Repudiation Tests
- [ ] `tests/manual/evidence/verify_success.txt` - Successful verification
- [ ] `tests/manual/evidence/verify_tamper_detected.txt` - Hash mismatch detection
- [ ] `tests/manual/evidence/verify_sig_fail.txt` - Invalid signature detection
- [ ] Sample transcript and receipt files

#### 6. Additional Evidence
- [ ] Database screenshot showing user records with salted hashes
- [ ] Certificate chain diagram (CA → Server/Client)
- [ ] Test report document summarizing all findings

---

## 🧩 Additional Functional Tests

### Test 6: Multiple Users / Concurrent Sessions
**Objective:** Verify system handles multiple users correctly.

**Steps:**
1. Register 3 different users:
   - User A: `alice@example.com` / `alice` / `pass123`
   - User B: `bob@example.com` / `bob` / `pass456`
   - User C: `charlie@example.com` / `charlie` / `pass789`

2. Test sequential sessions:
```powershell
# Session 1: Alice
python -m app.client
# Login as alice, send 3 messages, quit

# Session 2: Bob
python -m app.client
# Login as bob, send 3 messages, quit

# Session 3: Charlie
python -m app.client
# Login as charlie, send 3 messages, quit
```

3. Verify separate transcripts created:
   - `transcripts/client_alice_*.txt`
   - `transcripts/client_bob_*.txt`
   - `transcripts/client_charlie_*.txt`

4. Verify separate receipts generated

**Expected Result:**
- Each user has independent transcript
- Sequence numbers restart at 1 for each session
- No cross-contamination between user transcripts

---

### Test 7: Registration Edge Cases
**Objective:** Test registration validation.

**Test Cases:**

#### A. Duplicate Username
```powershell
# Register user
python -m app.client
# Select: 1 (Register)
# Email: test@example.com
# Username: testuser
# Password: pass123
# [OK] Registration successful

# Try duplicate username
python -m app.client
# Select: 1 (Register)
# Email: another@example.com
# Username: testuser  # Same username
# Password: different456
```

**Expected Output:**
```
[!] Registration failed: Username already exists
```

#### B. Duplicate Email
```powershell
# Try duplicate email
python -m app.client
# Select: 1 (Register)
# Email: test@example.com  # Already registered
# Username: newuser
# Password: pass789
```

**Expected Output:**
```
[!] Registration failed: Email already registered
```

#### C. Empty Password
**Expected:** Validation error or minimum length enforcement

---

### Test 8: Login Edge Cases
**Objective:** Test authentication robustness.

#### A. Wrong Password
```powershell
python -m app.client
# Select: 2 (Login)
# Email: usi@example.com
# Username: usi
# Password: WRONG_PASSWORD
```

**Expected Output:**
```
[!] LOGIN_FAIL: Invalid credentials
Connection terminated.
```

#### B. Non-existent User
```powershell
# Select: 2 (Login)
# Email: nonexistent@example.com
# Username: ghost
# Password: anything
```

**Expected Output:**
```
[!] LOGIN_FAIL: User not found
Connection terminated.
```

#### C. Email/Username Mismatch
```powershell
# Select: 2 (Login)
# Email: user1@example.com  # Valid email
# Username: different_user  # Wrong username for this email
# Password: correct_password
```

**Expected Output:**
```
[!] LOGIN_FAIL: Email and username do not match
Connection terminated.
```

---

### Test 9: Session Termination Scenarios
**Objective:** Test graceful and abrupt disconnection.

#### A. Graceful Quit
```
# Normal quit command
You: quit
[*] Disconnecting gracefully...
[*] Generating SessionReceipt...
[+] Receipt saved: receipts/client_usi_<timestamp>_receipt.json
```

#### B. Ctrl+C Interruption
```
# Press Ctrl+C during chat
^C
[*] Interrupted - cleaning up...
[*] Generating SessionReceipt...
[+] Receipt saved
```

#### C. Server Disconnect
```
# Kill server process while client is connected
[!] Server disconnected
[*] Generating SessionReceipt...
```

**Verify:** Receipts still generated in all cases

---

### Test 10: Performance / Stress Test
**Objective:** Test system under load.

**Steps:**
1. Send 100 consecutive messages rapidly:
```python
# In client, modify to send batch
for i in range(100):
    send_message(f"Stress test message {i}")
```

2. Verify:
   - All 100 messages logged in transcript
   - Sequence numbers 1-100 in order
   - No dropped messages
   - Receipt shows first_seq=1, last_seq=100

**Expected Result:**
- System handles 100+ messages without errors
- Transcript integrity maintained
- Performance acceptable (<1s per message)

---

### Test 11: Encrypted Content Verification
**Objective:** Verify different ciphertext for same plaintext.

**Steps:**
1. Send same message twice:
```
You: Hello
You: Hello
```

2. Examine transcript:
```powershell
type transcripts\client_*.txt
```

**Expected Result:**
- Both messages have DIFFERENT ciphertext (due to random IV)
- Example:
```
1|...|umWlFIFidq6j...|...|...
2|...|XpQrSTuvWxYz...|...|...  # Different ciphertext!
```

This proves:
- IV randomization working
- No deterministic encryption (security)
- AES-CBC mode functioning correctly

---

### Test 12: Database Security Check
**Objective:** Verify passwords are never stored in plaintext.

**Steps:**
1. Register user with password: `MySecretPassword123`

2. Check database:
```sql
mysql -u securechat_user -p
USE securechat;
SELECT username, HEX(salt), pwd_hash FROM users WHERE username='testuser';
```

**Expected Result:**
```
+----------+----------------------------------+------------------------------------------------------------------+
| username | salt                             | pwd_hash                                                         |
+----------+----------------------------------+------------------------------------------------------------------+
| testuser | A3B5C7D9E1F3...                 | 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 |
+----------+----------------------------------+------------------------------------------------------------------+
```

**Verify:**
- `salt` is 16 random bytes (32 hex chars)
- `pwd_hash` is 64 hex chars (SHA-256)
- NO plaintext password visible
- Different users have different salts

---

### Test 13: Certificate Chain Validation
**Objective:** Verify proper PKI hierarchy.

**Steps:**
1. Examine certificate relationships:
```powershell
# View CA certificate
openssl x509 -in certs/ca_cert.pem -text -noout

# View server certificate
openssl x509 -in certs/server_cert.pem -text -noout

# Verify server cert is signed by CA
openssl verify -CAfile certs/ca_cert.pem certs/server_cert.pem
```

**Expected Output:**
```
certs/server_cert.pem: OK
```

2. Verify client certificate:
```powershell
openssl verify -CAfile certs/ca_cert.pem certs/client_cert.pem
```

**Expected Output:**
```
certs/client_cert.pem: OK
```

**Verify:**
- CA is self-signed root
- Server and client certificates issued by CA
- Certificate validation chain correct

---

## 🔍 Additional Notes

### Platform-Specific Considerations
- **Windows:** Client uses `msvcrt.kbhit()` for non-blocking stdin (select.select doesn't support stdin on Windows)
- **Linux/Mac:** Both client and server can use select.select() for stdin
- Server on Windows: Cannot send messages (stdin limitation) - receive-only mode

### Cryptographic Implementations
- **AES Mode:** Using AES-128-CBC (not ECB as in spec) - CBC provides better security
- **IV Handling:** Random 16-byte IV prepended to each ciphertext
- **Padding:** PKCS#7 padding for AES block alignment
- **DH Group:** RFC 3526 2048-bit MODP group (secure parameter)
- **Key Derivation:** K = Trunc16(SHA256(big_endian(Ks)))
- **Signatures:** RSA PKCS#1 v1.5 with SHA-256 (industry standard)

### Security Considerations
- All sensitive data encrypted before transmission
- Perfect Forward Secrecy via ephemeral DH keys per session
- Non-repudiation through RSA signatures on all messages
- Replay protection via monotonic sequence numbers
- Certificate-based authentication (mutual TLS-like handshake)
- Password hashing: SHA-256(salt || password) with random 16-byte salt

### Known Limitations
1. Server cannot send messages on Windows (platform stdin limitation)
2. Single-threaded server (handles one client at a time)
3. No session resumption (each connection requires full handshake)
4. Transcripts grow unbounded (no rotation mechanism)
5. In-memory seqno tracking (lost on crash - could persist to DB)

### Assignment Specification Deviations
- **AES Mode:** Implemented CBC instead of ECB (security improvement)
  - Justification: ECB is insecure (same plaintext → same ciphertext)
  - CBC provides semantic security with random IVs
- **Project Structure:** Used `app/client.py` and `app/server.py` (not `client/` and `server/` dirs)
  - Simplifies imports and module organization

### Testing Priority Order
1. **CRITICAL (Required for submission):**
   - Wireshark capture (proves encryption)
   - Transcript verification (proves non-repudiation)
   - BAD_CERT test (proves PKI validation)

2. **IMPORTANT (Strongly recommended):**
   - SIG_FAIL test (proves tamper detection)
   - REPLAY test (proves sequence number protection)

3. **OPTIONAL (Completeness):**
   - Multiple users test
   - Edge cases (registration, login)
   - Performance test
   - Database inspection

### Evidence Organization
Create directory structure:
```
tests/manual/evidence/
├── wireshark/
│   ├── encrypted-traffic.pcapng
│   └── tcp-stream-screenshot.png
├── bad_cert/
│   ├── self-signed-rejection.txt
│   ├── expired-rejection.txt
│   └── cn-mismatch-rejection.txt
├── sig_fail/
│   └── tamper-detection.txt
├── replay/
│   └── replay-rejection.txt
├── verification/
│   ├── success.txt
│   ├── tamper-detected.txt
│   └── sig-fail.txt
└── transcripts/
    ├── sample-transcript.txt
    └── sample-receipt.json
```

### Submission Checklist
- [ ] All test evidence files collected
- [ ] Screenshots with timestamps
- [ ] Test report document (PDF/Word)
- [ ] Source code with comments
- [ ] Database schema documentation
- [ ] Certificate files (CA, server, client)
- [ ] README with setup instructions
- [ ] Git repository with commit history

---

## 🚀 Quick Test Execution Guide

### Minimal Test Suite (30 minutes)
```powershell
# 1. Wireshark capture (5 min)
# Start Wireshark → Run server → Run client → Chat → Save pcapng

# 2. Transcript verification (5 min)
python scripts/verify_transcript.py
# Test success case and tamper case

# 3. BAD_CERT test (10 min)
# Generate self-signed cert → Test rejection → Restore original

# 4. Database check (5 min)
mysql -u securechat_user -p
SELECT * FROM users;  # Verify salted hashes

# 5. Certificate validation (5 min)
openssl verify -CAfile certs/ca_cert.pem certs/server_cert.pem
```

### Complete Test Suite (2 hours)
Execute all 13 tests in order, collect evidence for each.

---

## 📞 Troubleshooting Common Issues

### Issue: "Module not found" errors
**Solution:**
```powershell
pip install -r requirements.txt
```

### Issue: Database connection failed
**Solution:**
```powershell
# Check MySQL is running
mysql -u root -p
# Verify .env file has correct credentials
```

### Issue: Certificate validation fails
**Solution:**
```powershell
# Regenerate certificates
python scripts/gen_ca.py
python scripts/gen_cert.py server
python scripts/gen_cert.py client
```

### Issue: Windows stdin not working
**Solution:** Already implemented with msvcrt.kbhit() - no action needed

### Issue: Port already in use
**Solution:**
```powershell
# Find process using port 5000
netstat -ano | findstr :5000
# Kill process
taskkill /PID <pid> /F
```

---

**Last Updated:** January 12, 2025  
**Test Suite Version:** 2.0  
**Assignment:** SecureChat - Infosec Assignment #2
