# SecureChat Manual Testing Checklist

## 🧪 Test Evidence Requirements (Assignment #2)

### 1. ✅ Wireshark Capture - Encrypted Payloads Only
**Objective:** Demonstrate that all sensitive data is encrypted at the application layer.

**Test Steps:**
1. Start Wireshark capture on loopback interface (127.0.0.1)
2. Run server: `python -m app.server`
3. Run client: `python -m app.client`
4. Complete registration → login → send chat messages
5. Stop Wireshark capture

**Expected Result:**
- TCP packets visible but payloads are encrypted (Base64-encoded ciphertext)
- No plaintext passwords, usernames, or chat messages visible
- Only protocol metadata (message types) visible in JSON

**Evidence File:** `wireshark-encrypted-traffic.pcapng`

---

### 2. ✅ BAD_CERT - Invalid/Self-Signed Certificate Rejection
**Objective:** Verify certificate validation rejects invalid certificates.

**Test Scenarios:**

#### A. Invalid CA Signature
1. Generate a self-signed certificate (not signed by trusted CA)
2. Replace server/client cert with self-signed cert
3. Attempt connection

**Expected Output:**
```
[!] BAD_CERT: Invalid CA signature
```

#### B. Expired Certificate
1. Manually edit certificate dates or use OpenSSL to create expired cert
2. Attempt connection

**Expected Output:**
```
[!] BAD_CERT: Certificate has expired
```

#### C. Wrong Common Name (CN)
1. Use server certificate for client (CN mismatch)
2. Attempt connection

**Expected Output:**
```
[!] BAD_CERT: Common Name mismatch
```

**Evidence:** Screenshots showing rejection messages

---

### 3. ✅ SIG_FAIL - Tamper Detection via Signature Verification
**Objective:** Demonstrate that message tampering is detected through signature verification failure.

**Test Steps:**
1. Establish encrypted chat session
2. Intercept a ChatMessage (can be done programmatically or via network proxy)
3. Flip one bit in the ciphertext (ct field)
4. Forward modified message to recipient

**Expected Output:**
```
[!] SIG_FAIL: Message signature verification failed
```

**Code for Tamper Test:**
```python
# In client.py or separate test script
def tamper_test(message_json):
    msg = json.loads(message_json)
    ct_bytes = base64.b64decode(msg['ct'])
    # Flip first bit
    tampered = bytes([ct_bytes[0] ^ 0x01]) + ct_bytes[1:]
    msg['ct'] = base64.b64encode(tampered).decode()
    return json.dumps(msg)
```

**Evidence:** Server/client logs showing SIG_FAIL rejection

---

### 4. ✅ REPLAY - Sequence Number Protection
**Objective:** Verify replay attack detection using sequence number validation.

**Test Steps:**
1. Capture a valid ChatMessage with seqno=5
2. After sending messages with seqno=6, 7, 8
3. Replay the captured message with seqno=5

**Expected Output:**
```
[!] REPLAY: Rejected message with seqno 5 (expected > 8)
```

**Implementation Check:**
```python
# In message receive handler
if seqno <= self.last_seqno:
    print(f"[!] REPLAY: Rejected message with seqno {seqno}")
    return False
```

**Evidence:** Console output showing REPLAY rejection

---

### 5. ✅ Non-Repudiation - Transcript & SessionReceipt Verification
**Objective:** Demonstrate offline verification of session transcripts with digital signatures.

**Test Steps:**

#### A. Generate Transcript During Chat Session
1. Complete chat session with multiple messages
2. Verify transcript file created in `transcripts/session_<timestamp>.txt`
3. Verify SessionReceipt JSON created: `transcripts/session_<timestamp>_receipt.json`

**Transcript Format:**
```
1|1700000001000|ZW5jcnlwdGVk...|c2lnbmF0dXJl...|abc123fingerprint
2|1700000002000|ZW5jcnlwdGVk...|c2lnbmF0dXJl...|abc123fingerprint
```

**SessionReceipt Format:**
```json
{
  "peer": "client",
  "first_seq": 1,
  "last_seq": 10,
  "transcript_sha256": "abc123...",
  "sig": "base64_signature..."
}
```

#### B. Offline Verification
1. Run verification script: `python scripts/verify_transcript.py`
2. Provide transcript file path
3. Provide SessionReceipt JSON path
4. Provide peer certificate path

**Expected Output:**
```
[OK] Message 1: Signature valid
[OK] Message 2: Signature valid
...
[OK] All message signatures valid
[OK] Transcript hash matches: abc123...
[OK] SessionReceipt signature valid
✓ Transcript verification PASSED
```

#### C. Tamper Detection Test
1. Modify one line in transcript file (change ciphertext)
2. Re-run verification

**Expected Output:**
```
[FAIL] Transcript hash mismatch
✗ Transcript verification FAILED - Tamper detected
```

**Evidence:**
- `transcripts/` directory contents
- Verification script output (success and tamper cases)

---

## 📝 Summary Checklist

- [ ] Wireshark .pcapng showing encrypted traffic
- [ ] Screenshots of BAD_CERT rejections (3 scenarios)
- [ ] Console output showing SIG_FAIL on tampered message
- [ ] Console output showing REPLAY rejection
- [ ] Transcript + SessionReceipt files
- [ ] Verification script output (both success and tamper)

---

## 🔍 Additional Notes

- All tests should be documented with timestamps and system configuration
- Include both positive (expected behavior) and negative (rejection) test cases
- Ensure test environment uses application-layer crypto (no TLS/SSL)
- Document any deviations from assignment specification (e.g., CBC vs ECB)
