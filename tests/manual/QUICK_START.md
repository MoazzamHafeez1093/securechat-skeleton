# 🚀 Quick Testing Guide

## What You Actually Need (Per Assignment Spec)

**Test these 5 things:**
1. Wireshark - encrypted traffic
2. BAD_CERT - certificate rejection
3. SIG_FAIL - tamper detection (optional but recommended)
4. REPLAY - replay protection (optional but recommended)
5. Non-Repudiation - transcript verification

**Put evidence in:** `TestReport-A02.docx` (Word document with screenshots)  
**NOT in GitHub repo** - just code and README

---

## Priority Tests

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

**For submission:** Screenshot in Word doc, save `.pcapng` locally

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
5. **For submission:** Screenshot in Word doc

**Tamper Test:**
1. Edit transcript file (change one character in ciphertext)
2. Re-run verification
3. Screenshot "✗ VERIFICATION FAILED" with hash mismatch
4. **For submission:** Screenshot in Word doc

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

**For submission:** Screenshot rejection in Word doc

---

## Optional Tests (Recommended)

### 4️⃣ SIG_FAIL - Tamper Detection (20 minutes)

**Manual Method:**
1. Modify `app/client.py` to add test function (see NOTES.md for code)
2. During chat, trigger tamper test
3. Server should print: `[!] SIG_FAIL: Message signature verification failed`
4. **For submission:** Screenshot in Word doc

---

### 5️⃣ REPLAY - Sequence Protection (20 minutes)

**Manual Method:**
1. Send 3 normal messages (seqno 1, 2, 3)
2. Manually resend message with seqno=2 (modify client to replay)
3. Server should reject: `[!] REPLAY: Rejected message with seqno 2 (expected > 3)`
4. **For submission:** Screenshot in Word doc

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

```

---

## 📋 What to Submit on GCR

1. **GitHub Repo ZIP** - Downloaded from your fork
2. **MySQL Dump** - Schema + sample records
3. **README.md** - Execution steps, config, sample I/O
4. **Report-A02.docx** - Implementation details
5. **TestReport-A02.docx** - All test screenshots and evidence

**Important:** Evidence goes in Word docs, NOT in GitHub repo!

---

## ⚡ Fastest Path (45 minutes)

```powershell
# 1. Wireshark
# Start Wireshark → Run server/client → Chat → Save pcapng → Screenshot

# 2. Verification
python scripts/verify_transcript.py
# Success + tamper case → Screenshots for Word doc

# 3. BAD_CERT
# Generate self-signed → Test → Screenshot → Restore
```

**Result:** Core evidence for TestReport-A02.docx

---

## 🆘 Quick Troubleshooting

| Issue | Solution |
|-------|----------|
| Port 5000 in use | `netstat -ano \| findstr :5000` then `taskkill /PID <pid> /F` |
| MySQL error | Check `.env` credentials, verify MySQL running |
| Module not found | `pip install -r requirements.txt` |
| Wireshark no packets | Use "Loopback" adapter, filter `tcp.port == 5000` |

---

**Last Updated:** January 12, 2025  
**Focus:** Follow assignment spec exactly - evidence in Word docs, code in GitHub
