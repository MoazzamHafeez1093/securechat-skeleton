# 🚀 Quick Start Testing Guide

## Priority Tests (Must Complete)

### 1️⃣ Wireshark Capture (15 minutes)

**Steps:**
1. Install Wireshark: https://www.wireshark.org/download.html
2. Open Wireshark → Select "Loopback" interface
3. Click blue shark fin to start capture
4. Filter: `tcp.port == 5000`
5. Run server: `python -m app.server`
6. Run client: `python -m app.client`
7. Login and send 5 messages
8. Type `quit` to disconnect
9. Stop Wireshark (red square)
10. Save as: `tests/manual/evidence/wireshark/encrypted-traffic.pcapng`

**Verify:** Right-click packet → Follow TCP Stream → See encrypted JSON (no plaintext)

---

### 2️⃣ Transcript Verification (10 minutes)

**Steps:**
1. Complete a chat session (generates transcript + receipt)
2. Run: `python scripts/verify_transcript.py`
3. Enter paths when prompted:
   - Transcript: `transcripts/client_usi_<timestamp>.txt`
   - Receipt: `receipts/client_usi_<timestamp>_receipt.json`
   - Cert: `certs/server_cert.pem`
4. Screenshot the "✓ VERIFICATION PASSED" output
5. Save to: `tests/manual/evidence/verification/success.txt`

**Tamper Test:**
1. Edit transcript file (change one character in ciphertext)
2. Re-run verification
3. Screenshot "✗ VERIFICATION FAILED" with hash mismatch
4. Save to: `tests/manual/evidence/verification/tamper-detected.txt`

---

### 3️⃣ BAD_CERT Test (15 minutes)

**Test Self-Signed Cert Rejection:**

```powershell
# Backup original
cd certs
copy server_cert.pem server_cert.pem.backup
copy server_key.pem server_key.pem.backup

# Generate self-signed cert (not CA-signed)
openssl req -x509 -newkey rsa:2048 -nodes -keyout server_key.pem -out server_cert.pem -days 365 -subj "/CN=localhost"

# Test - should reject
# Terminal 1:
python -m app.server

# Terminal 2:
python -m app.client
# Observe: [!] BAD_CERT rejection

# Restore
copy server_cert.pem.backup server_cert.pem
copy server_key.pem.backup server_key.pem
```

**Save output:** `tests/manual/evidence/bad_cert/self-signed-rejection.txt`

---

## Optional Tests (Recommended)

### 4️⃣ SIG_FAIL - Tamper Detection (20 minutes)

**Manual Method:**
1. Modify `app/client.py` to add test function (see NOTES.md for code)
2. During chat, trigger tamper test
3. Server should print: `[!] SIG_FAIL: Message signature verification failed`
4. Save output: `tests/manual/evidence/sig_fail/tamper-detection.txt`

---

### 5️⃣ REPLAY - Sequence Protection (20 minutes)

**Manual Method:**
1. Send 3 normal messages (seqno 1, 2, 3)
2. Manually resend message with seqno=2 (modify client to replay)
3. Server should reject: `[!] REPLAY: Rejected message with seqno 2 (expected > 3)`
4. Save output: `tests/manual/evidence/replay/replay-rejection.txt`

---

### 6️⃣ Database Security Check (5 minutes)

```powershell
mysql -u securechat_user -p
```

```sql
USE securechat;
SELECT username, HEX(salt), pwd_hash FROM users;
```

**Verify:**
- Passwords are NOT plaintext
- Each user has unique 16-byte salt
- pwd_hash is 64 hex characters (SHA-256)

**Screenshot:** Save as `tests/manual/evidence/database-security.png`

---

### 7️⃣ Certificate Validation (5 minutes)

```powershell
# Verify server cert signed by CA
openssl verify -CAfile certs/ca_cert.pem certs/server_cert.pem
# Expected: certs/server_cert.pem: OK

# Verify client cert signed by CA
openssl verify -CAfile certs/ca_cert.pem certs/client_cert.pem
# Expected: certs/client_cert.pem: OK
```

---

## 📋 Evidence Checklist

### Critical (Required)
- [ ] `wireshark/encrypted-traffic.pcapng`
- [ ] `wireshark/tcp-stream-screenshot.png`
- [ ] `verification/success.txt`
- [ ] `verification/tamper-detected.txt`
- [ ] `bad_cert/self-signed-rejection.txt`

### Important (Strongly Recommended)
- [ ] `sig_fail/tamper-detection.txt`
- [ ] `replay/replay-rejection.txt`
- [ ] Database security screenshot

### Optional (Bonus)
- [ ] `bad_cert/expired-rejection.txt`
- [ ] `bad_cert/cn-mismatch-rejection.txt`
- [ ] Multiple users test evidence

---

## ⚡ Fastest Path (Minimal Evidence - 45 minutes)

```powershell
# 1. Wireshark (15 min)
# Start Wireshark → Run server/client → Chat → Save pcapng

# 2. Transcript Verification (10 min)
python scripts/verify_transcript.py
# Test success + tamper case

# 3. BAD_CERT (15 min)
# Generate self-signed → Test rejection → Restore

# 4. Screenshots (5 min)
# Capture all console outputs
```

**Result:** Core evidence covering encryption, non-repudiation, and PKI validation.

---

## 🎯 Testing Order

1. **Day 1:** Wireshark + Transcript Verification (confidence builders)
2. **Day 2:** BAD_CERT + Database Check (security validation)
3. **Day 3:** SIG_FAIL + REPLAY (attack resistance)
4. **Day 4:** Edge cases + Documentation

---

## 🆘 Quick Troubleshooting

| Issue | Solution |
|-------|----------|
| Port 5000 in use | `netstat -ano \| findstr :5000` then `taskkill /PID <pid> /F` |
| MySQL connection failed | Check `.env` file, verify MySQL running |
| Module not found | `pip install -r requirements.txt` |
| Certificate error | Regenerate: `python scripts/gen_ca.py` |
| Wireshark shows no packets | Use "Loopback" adapter, filter `tcp.port == 5000` |

---

## 📞 Need Help?

See detailed instructions in `NOTES.md` for:
- Complete test procedures (13 test scenarios)
- Code examples for automated tests
- Expected outputs for all tests
- Troubleshooting guide
- Assignment specification deviations

---

**Last Updated:** January 12, 2025  
**Estimated Total Time:** 1.5 - 2 hours for all tests
